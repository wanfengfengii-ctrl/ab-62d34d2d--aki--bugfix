"""Certificate graph construction and whole-graph path building.

Nodes are distinct DER certificates (identified by SHA-256). Edges link a
child to every certificate that can issuer-name/key identify itself as the
child's issuer and whose real signature verifies. Cross-signs, duplicates and
cycles are native to the graph; path search never collapses it to a single
shortest chain before revocation checking.

Issuer candidate prefiltering (identical semantics online and offline):

* when the child carries an AKI keyIdentifier, same-subject candidates are
  restricted to certificates whose SKI matches, whose SKI is absent
  (compatibility — the issuer may predate RFC 5280 §4.2.1.1), or that carry
  the *same public key* as the referenced SKI owner (same-key cross-signs,
  including certificates without an SKI extension);
* when the child carries no AKI, the whole same-subject candidate set is
  examined.

The filter runs over cheaply extracted identity material (no full DER parse),
so hundreds of thousands of AKI-mismatched same-subject decoys add no
per-adjudication parse work.
"""
from __future__ import annotations

import dataclasses
import hashlib

from .certmodel import ParsedCert, verify_cert_signature


def identity_compatible(child_aki: bytes | None, iss_ski: bytes | None,
                        iss_key_id: str,
                        target_key_ids: frozenset[str]) -> bool:
    """Pure identity rule (RFC 5280 name/AKI matching plus same-key cross-sign
    preservation). ``target_key_ids`` are the public-key ids owned by
    same-subject certificates carrying the SKI the child's AKI references."""
    if child_aki is None or iss_ski is None or iss_ski == child_aki:
        return True
    return iss_key_id in target_key_ids


@dataclasses.dataclass
class Edge:
    child: str
    issuer: str
    # Intrinsic edge checks (path independent).
    sig_ok: bool
    sig_rule: str | None
    name_key_ok: bool


class CertGraph:
    def __init__(self, certs: dict[str, ParsedCert]):
        self.certs = certs
        # subject name DER -> fingerprints
        self.by_name: dict[bytes, list[str]] = {}
        # (name, key bytes) -> fingerprints
        self.by_name_key: dict[tuple[bytes, bytes], list[str]] = {}
        for fp, pc in certs.items():
            self.by_name.setdefault(pc.subject_der, []).append(fp)
            self.by_name_key.setdefault(
                (pc.subject_der, pc.spki_bitstring), []).append(fp)
        for v in self.by_name.values():
            v.sort()
        for v in self.by_name_key.values():
            v.sort()
        self._edge_cache: dict[tuple[str, str], Edge] = {}

    def _ski_target_key_ids(self, name_der: bytes,
                            aki: bytes | None) -> frozenset[str]:
        """Public-key ids of fully parsed same-subject certificates whose SKI
        equals ``aki``. The lazy subclass resolves this from the cheap index
        instead, so it works before (and regardless of) full parsing."""
        if aki is None:
            return frozenset()
        out = set()
        for fp in self.by_name.get(name_der, ()):
            pc = self.certs.get(fp)
            if pc is not None and pc.ski == aki:
                out.add(hashlib.sha256(pc.spki_bitstring).hexdigest())
        return frozenset(out)

    def by_issuer(self, name_der: bytes, aki: bytes | None) -> list[ParsedCert]:
        out: list[ParsedCert] = []
        target_keys = self._ski_target_key_ids(name_der, aki)
        for fp in self.by_name.get(name_der, []):
            pc = self.certs[fp]
            key_id = hashlib.sha256(pc.spki_bitstring).hexdigest()
            if identity_compatible(aki, pc.ski, key_id, target_keys):
                out.append(pc)
        return out

    def edge(self, child_fp: str, issuer_fp: str) -> Edge:
        key = (child_fp, issuer_fp)
        cached = self._edge_cache.get(key)
        if cached is not None:
            return cached
        child = self.certs[child_fp]
        issuer = self.certs[issuer_fp]
        target_keys = self._ski_target_key_ids(child.issuer_der, child.aki)
        iss_key_id = hashlib.sha256(issuer.spki_bitstring).hexdigest()
        name_key_ok = (
            child.issuer_der == issuer.subject_der
            and identity_compatible(child.aki, issuer.ski, iss_key_id,
                                    target_keys))
        if not name_key_ok:
            e = Edge(child_fp, issuer_fp, False, "ISSUER_NAME_KEY", False)
        else:
            ok, rule = verify_cert_signature(child, issuer)
            e = Edge(child_fp, issuer_fp, ok, rule, True)
        self._edge_cache[key] = e
        return e

    def candidate_issuers(self, child_fp: str) -> list[str]:
        """Name/key-compatible issuers, signature not necessarily valid yet."""
        child = self.certs[child_fp]
        return list(self.by_name.get(child.issuer_der, []))

    def get_cert(self, fp: str) -> ParsedCert | None:
        return self.certs.get(fp)
