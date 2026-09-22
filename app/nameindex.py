"""Seal-time issuer-identity indexes built with zero cryptographic work.

The v1 sidecar indexed certificates only by subject Name DER, so finding a
certificate's issuers fully parsed *every* same-subject certificate: hundreds
of same-name decoy CAs with non-matching SKIs were parsed on every
adjudication. The v2 index additionally maps, per subject name:

* SKI -> certificate digests (for direct AKI keyIdentifier matching);
* SHA-256(subjectPublicKey bytes) -> digests (same-key cross-signs, which an
  AKI match must never prune);
* the set of certificates carrying no SKI extension (kept for compatibility
  with issuers that cannot be identified by SKI).

All fields are extracted from raw DER (``cheap_identity``); no signature or
full certificate parsing happens while building these indexes.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib

from .certmodel import cheap_identity, cheap_names
from .errors import MalformedEvidenceError

INDEX_VERSION = 2
INDEX_VERSION_V1 = 1


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def build_sidecar(digests, get_blob) -> dict:
    """Build the JSON-serializable v2 sidecar from raw certificate DER."""
    names: dict[str, list[str]] = {}
    skis: dict[str, dict[str, list[str]]] = {}
    keys: dict[str, dict[str, list[str]]] = {}
    noski: dict[str, list[str]] = {}
    for d in digests:
        blob = get_blob(d)
        ident = None
        try:
            ident = cheap_identity(blob)
        except MalformedEvidenceError:
            # The name bucket must stay as permissive as the v1 sidecar:
            # keep a certificate whenever its issuer/subject Name is
            # readable, even if richer identity extraction fails.
            try:
                _issuer, subject = cheap_names(blob)
            except MalformedEvidenceError:
                continue
        name = _b64(ident.subject_der if ident is not None else subject)
        names.setdefault(name, []).append(d)
        if ident is None:
            continue
        kh = hashlib.sha256(ident.spki_bitstring).hexdigest()
        keys.setdefault(name, {}).setdefault(kh, []).append(d)
        if ident.ski is None:
            noski.setdefault(name, []).append(d)
        else:
            skis.setdefault(name, {}).setdefault(_b64(ident.ski), []).append(d)
    for v in names.values():
        v.sort()
    for v in noski.values():
        v.sort()
    for by_ski in skis.values():
        for v in by_ski.values():
            v.sort()
    for by_key in keys.values():
        for v in by_key.values():
            v.sort()
    return {"v": INDEX_VERSION, "names": names, "ski": skis,
            "key": keys, "noski": noski}


@dataclasses.dataclass
class NameIndex:
    version: int
    # subject Name DER -> digests
    by_name: dict[bytes, list[str]]
    # subject Name DER -> {SKI: digests}
    by_name_ski: dict[bytes, dict[bytes, list[str]]]
    # subject Name DER -> {sha256(raw key bytes): digests}
    keys_by_name: dict[bytes, dict[bytes, list[str]]]
    # subject Name DER -> digests of certs carrying no SKI extension
    no_ski: dict[bytes, list[str]]

    @classmethod
    def from_sidecar(cls, raw: dict) -> "NameIndex":
        # v1 sidecars were the bare mapping {name_b64: [digests]}; v2 wraps
        # the data in an object carrying a version and extra indexes.
        if not isinstance(raw, dict) or "v" not in raw:
            version = INDEX_VERSION_V1
            names_raw = raw
            ski_raw = key_raw = noski_raw = {}
        else:
            version = raw["v"]
            names_raw = raw.get("names", {})
            ski_raw = raw.get("ski", {})
            key_raw = raw.get("key", {})
            noski_raw = raw.get("noski", {})
        by_name: dict[bytes, list[str]] = {}
        for name_b64, ds in names_raw.items():
            by_name[base64.b64decode(name_b64)] = list(ds)
        by_name_ski: dict[bytes, dict[bytes, list[str]]] = {}
        keys_by_name: dict[bytes, dict[bytes, list[str]]] = {}
        no_ski: dict[bytes, list[str]] = {}
        if version >= INDEX_VERSION:
            for name_b64, by_ski in ski_raw.items():
                name = base64.b64decode(name_b64)
                by_name_ski[name] = {
                    base64.b64decode(ski_b64): list(ds)
                    for ski_b64, ds in by_ski.items()}
            for name_b64, by_key in key_raw.items():
                name = base64.b64decode(name_b64)
                keys_by_name[name] = {
                    bytes.fromhex(kh): list(ds) for kh, ds in by_key.items()}
            for name_b64, ds in noski_raw.items():
                no_ski[base64.b64decode(name_b64)] = list(ds)
        return cls(version, by_name, by_name_ski, keys_by_name, no_ski)

    def select(self, name_der: bytes, aki: bytes | None) -> list[str]:
        """Issuer digests worth fully parsing for a child with this issuer
        Name and AKI.

        * Child without AKI (or v1 data): the whole same-name bucket must be
          examined.
        * Child with AKI: issuers whose SKI matches, issuers without an SKI
          (compatibility), plus every certificate sharing the public key of
          any such candidate (same-key cross-signs). Same-name certificates
          with a different, present SKI are provably not name/key-compatible
          and are skipped without full parsing.
        """
        if aki is None or self.version < INDEX_VERSION:
            return sorted(self.by_name.get(name_der, ()))
        matched: set[str] = set(self.by_name_ski.get(name_der, {}).get(aki, ()))
        matched.update(self.no_ski.get(name_der, ()))
        groups = self.keys_by_name.get(name_der)
        if groups:
            key_of: dict[str, bytes] = {}
            for kh, ds in groups.items():
                for d in ds:
                    key_of[d] = kh
            for d in list(matched):
                kh = key_of.get(d)
                if kh is not None:
                    matched.update(groups[kh])
        return sorted(matched)
