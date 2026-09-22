"""Materialize a sealed evidence set into lazily parsed indexes.

Certificates are parsed on first access (the acceptance load has 100k certs
but adjudicates a handful of leaves); revocation objects are parsed eagerly
(max 2,000) since the limits make that cheap and they are always needed for
evidence logging.

Same-subject issuer buckets are AKI-prefiltered on *cheap* identity material
(raw-DER Name/SKI/public-key digest — no cryptographic parse) before any
certificate is fully parsed. A leaf carrying an AKI therefore costs a constant
number of full parses regardless of how many SKI-mismatched same-subject
decoys the archive contains; a leaf without an AKI still examines the whole
bucket. Catalogs without the cheap SKI/key sidecar (sealed by older builds)
remain usable: identities are derived from the blobs lazily.
"""
from __future__ import annotations

import base64
import dataclasses

from . import evidence as ev
from .certmodel import (
    CheapIdentity,
    ParsedCert,
    cheap_identity,
    parse_certificate,
)
from .errors import MalformedEvidenceError, UnsupportedError
from .graph import CertGraph, identity_compatible


@dataclasses.dataclass(frozen=True)
class _CheapEntry:
    digest: str
    ski: bytes | None
    key_id: str  # sha256 hex of subjectPublicKey key bytes


class IdentityCatalog:
    """Subject-name buckets with cheap issuer-filtering identity.

    ``entries(name)`` returns ``(digest, ski, key_id)`` tuples. Entries whose
    sidecar predates the SKI/key material are resolved on demand with
    :func:`app.certmodel.cheap_identity` (raw DER only, no crypto) and cached.
    """

    def __init__(self, raw: dict[bytes, list[dict]], resolve):
        self._raw = raw
        self._resolve = resolve
        self._cache: dict[str, _CheapEntry] = {}

    def _entry(self, item: dict) -> _CheapEntry | None:
        d = item["d"] if "d" in item else item["digest"]
        if "k" in item or "key_id" in item:
            s = item.get("s")
            ski = base64.b64decode(s) if s is not None else None
            return _CheapEntry(d, ski, item.get("k") or item["key_id"])
        cached = self._cache.get(d)
        if cached is not None:
            return cached
        ident = self._resolve(d)  # raw DER only, never raises
        if ident is None:
            return None
        entry = _CheapEntry(d, ident.ski, ident.spki_key_id)
        self._cache[d] = entry
        return entry

    def entries(self, name_der: bytes) -> list[_CheapEntry]:
        out: list[_CheapEntry] = []
        for item in self._raw.get(name_der, ()):
            e = self._entry(item)
            if e is not None:
                out.append(e)
        return out

    def prefiltered(self, name_der: bytes, aki: bytes | None) -> list[str]:
        cands = [(e.digest, e.ski, e.key_id) for e in self.entries(name_der)]
        return _prefilter(aki, cands)

    def target_key_ids(self, name_der: bytes, aki: bytes | None) -> frozenset[str]:
        if aki is None:
            return frozenset()
        return frozenset(e.key_id for e in self.entries(name_der)
                         if e.ski == aki)


def _prefilter(child_aki: bytes | None,
               candidates: list[tuple[str, bytes | None, str]]) -> list[str]:
    ordered = sorted(candidates, key=lambda c: c[0])
    if child_aki is None:
        return [fp for fp, _s, _k in ordered]
    target_keys = frozenset(k for _fp, s, k in ordered if s == child_aki)
    out = []
    for fp, s, k in ordered:
        if identity_compatible(child_aki, s, k, target_keys):
            out.append(fp)
    return out


class LoadedSet:
    def __init__(self, store, manifest: dict):
        self.store = store
        self.manifest = manifest
        self.content = manifest["content"]
        self._parsed: dict[str, ParsedCert] = {}
        self.crls: dict[str, ev.CrlObject] = {}
        self.ocsps: dict[str, ev.OcspObject] = {}
        self.parse_problems: list[dict] = []
        self.full_parse_count = 0

    @classmethod
    def from_store(cls, store, manifest: dict) -> "LoadedSet":
        return cls(store, manifest)

    def get_blob(self, digest: str) -> bytes:
        return self.store.get_blob(digest)

    # -------------------------------------------------------- certificates
    def cert(self, digest: str) -> ParsedCert | None:
        if digest in self._parsed:
            return self._parsed[digest]
        self.full_parse_count += 1
        try:
            data = self.get_blob(digest)
            pc = parse_certificate(data)
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._parsed[digest] = None  # type: ignore[assignment]
            self.parse_problems.append({
                "sha256": digest, "kind": "certificate",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        self._parsed[digest] = pc
        return pc

    def all_cert_digests(self) -> list[str]:
        return list(self.content["certificates"])

    def build_graph(self, anchor_digests: set[str]) -> CertGraph:
        """Parse only anchor certs eagerly; everything else stays lazy and is
        reached through the cheap AKI-aware identity catalog."""
        certs: dict[str, ParsedCert] = {}
        for d in anchor_digests:
            pc = self.cert(d)
            if pc is not None:
                certs[d] = pc

        catalog = self.identity_catalog()

        class LazyGraph(CertGraph):
            def __init__(self_inner, loader, anchor_ds):
                self_inner.loader = loader
                self_inner.anchor_ds = anchor_ds
                self_inner.certs = certs
                self_inner.by_name = {}
                self_inner.by_name_key = {}
                self_inner._edge_cache = {}
                self_inner.catalog = catalog

            def _materialize(self_inner, digest: str) -> ParsedCert | None:
                if digest in self_inner.certs:
                    return self_inner.certs[digest]
                pc = self_inner.loader.cert(digest)
                if pc is None:
                    return None
                self_inner.certs[digest] = pc
                self_inner.by_name.setdefault(pc.subject_der, []).append(digest)
                self_inner.by_name_key.setdefault(
                    (pc.subject_der, pc.spki_bitstring), []).append(digest)
                return pc

            def get_cert(self_inner, digest: str) -> ParsedCert | None:
                return self_inner._materialize(digest)

            # Same-key cross-sign identity resolves from cheap identity
            # material, so it never forces a full parse of the SKI owner.
            def _ski_target_key_ids(self_inner, name_der, aki):
                return catalog.target_key_ids(name_der, aki)

        graph = LazyGraph(self, anchor_digests)

        def candidate_issuers(child_fp: str) -> list[str]:
            child = graph.certs.get(child_fp) or self.cert(child_fp)
            if child is None:
                return []
            survivors = catalog.prefiltered(child.issuer_der, child.aki)
            out = []
            for d in survivors:
                pc = graph._materialize(d)
                if pc is not None:
                    out.append(d)
            return sorted(out)

        graph.candidate_issuers = candidate_issuers  # type: ignore[assignment]

        # by_issuer used by revocation engine: resolve by name + AKI with the
        # same cheap prefilter (no-SKI and same-key candidates preserved).
        def by_issuer(name_der, aki):
            res = []
            for d in catalog.prefiltered(name_der, aki):
                pc = graph._materialize(d)
                if pc is not None:
                    res.append(pc)
            return res

        graph.by_issuer = by_issuer  # type: ignore[assignment]
        return graph

    # ------------------------------------------------- identity catalogs
    def identity_catalog(self) -> IdentityCatalog:
        cached = getattr(self, "_catalog", None)
        if cached is not None:
            return cached
        raw: dict[bytes, list[dict]] = {}
        v2 = self._load_v2_index()
        if v2 is not None:
            for name_b64, entries in v2.items():
                raw[base64.b64decode(name_b64)] = entries
        else:
            # Legacy stores (name-only sidecar, or no sidecar at all): keep
            # full subject-name query support; cheap SKI/key identity is
            # derived from blobs on first use.
            for name_der, digests in self._subject_name_index().items():
                raw[name_der] = [{"d": d} for d in digests]

        def resolve(digest: str) -> CheapIdentity | None:
            try:
                return cheap_identity(self.get_blob(digest))
            except MalformedEvidenceError:
                return None

        catalog = IdentityCatalog(raw, resolve)
        self._catalog = catalog
        return catalog

    def _load_v2_index(self) -> dict | None:
        import json
        import os

        path = self._v2_index_path()
        if not os.path.exists(path):
            return None
        with open(path) as f:
            doc = json.load(f)
        if not isinstance(doc, dict) or doc.get("version") != 2:
            return None
        return doc.get("names", {})

    def _v2_index_path(self) -> str:
        import os

        return os.path.join(self.store.root, "packages",
                            f"{self.manifest['evidence_set_id']}.identity.v2.json")

    def _subject_name_index(self) -> dict[bytes, list[str]]:
        """Legacy name-only index (raw Name DER keys, base64 sidecar)."""
        import json
        import os

        cached = getattr(self, "_name_idx", None)
        if cached is not None:
            return cached
        idx_path = self._name_index_path()
        idx: dict[bytes, list[str]] = {}
        if os.path.exists(idx_path):
            with open(idx_path) as f:
                raw_index = json.load(f)
            # Tolerate both v1 ({name: [digests]}) and stray v2 documents.
            if isinstance(raw_index, dict) and raw_index.get("version") == 2:
                for name_b64, entries in raw_index.get("names", {}).items():
                    idx[base64.b64decode(name_b64)] = [
                        e["d"] if isinstance(e, dict) else e for e in entries]
            else:
                for name_b64, digests in raw_index.items():
                    idx[base64.b64decode(name_b64)] = digests
        else:
            # Slow fallback for stores sealed before sidecars existed.
            for d in self.content["certificates"]:
                pc = self.cert(d)
                if pc is not None:
                    idx.setdefault(pc.subject_der, []).append(d)
        self._name_idx = idx
        return idx

    def _name_index_path(self) -> str:
        import os

        return os.path.join(self.store.root, "packages",
                            f"{self.manifest['evidence_set_id']}.nameindex.json")

    # --------------------------------------------------------- revocation
    def load_revocation(self) -> None:
        # Identical bytes archived multiple times: evidence is possessed at
        # the earliest recorded received_at.
        def _earliest(items):
            m: dict[str, int] = {}
            for item in items:
                d, r = item["sha256"], item["received_at"]
                m[d] = r if d not in m else min(m[d], r)
            return m
        for digest, received_at in _earliest(self.content["crls"]).items():
            try:
                raw = self.get_blob(digest)
                self.crls[digest] = ev.parse_crl(raw, received_at)
            except (UnsupportedError, MalformedEvidenceError) as exc:
                self.parse_problems.append({
                    "sha256": digest, "kind": "crl",
                    "code": exc.code, "message": exc.message, "detail": exc.detail})
        for digest, received_at in _earliest(self.content["ocsps"]).items():
            try:
                raw = self.get_blob(digest)
                self.ocsps[digest] = ev.parse_ocsp(raw, received_at)
            except (UnsupportedError, MalformedEvidenceError) as exc:
                self.parse_problems.append({
                    "sha256": digest, "kind": "ocsp",
                    "code": exc.code, "message": exc.message, "detail": exc.detail})
