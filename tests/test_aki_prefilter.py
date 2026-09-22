"""AKI-scoped issuer resolution regressions.

Covers the acceptance matrix:

* leaf with AKI: VALID through the real CA amid hundreds of same-subject
  decoys, with a constant number of full DER parses;
* leaf without AKI: the whole same-subject candidate set is examined;
* issuer without SKI: the no-SKI compatibility candidate is never dropped
  (chain building and CRL verification);
* same-key cross-signs (different SKI, or no SKI at all) are preserved;
* legacy sealed sets (name-only sidecar, or no sidecar at all) stay usable;
* fresh-process adjudication is byte-identical and the offline verifier
  recomputes the same result.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from tests import pki_factory as pf
from app import canonical
from app.adjudge import adjudicate
from app.certmodel import fp_of
from app.graph import identity_compatible
from app.loader import LoadedSet
from app.package import build_package
from app.storage import Store
from verify.verify_package import verify_package

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


# --------------------------------------------------------------- harness
class Harness:
    def __init__(self, tmp_path):
        self.tmp = str(tmp_path)
        self.store = Store(os.path.join(self.tmp, "data"))
        self.sid = "es_aki_000000000000000000000000000001"
        self.store.create_set(self.sid, "create")
        self.rows = []

    def add_cert(self, c):
        d = pf.der(c)
        self.store.put_blob(d)
        self.rows.append({"client_ref": "c" + fp_of(d)[:20],
                          "kind": "certificate", "content_sha256": fp_of(d),
                          "received_at": RECEIVED})

    def add_crl(self, c, i):
        d = pf.der(c)
        self.store.put_blob(d)
        self.rows.append({"client_ref": f"r{i}", "kind": "crl",
                          "content_sha256": fp_of(d), "received_at": RECEIVED})

    def seal(self):
        self.store.add_items(self.sid, self.rows)
        return self.store.seal(self.sid)

    def judge(self, leaf, root, leaf_key):
        d = hashlib.sha256(b"artifact").digest()
        s = leaf_key.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
        return adjudicate(self.store, self.sid, {
            "artifact_digest": d.hex(), "signature": s.hex(),
            "signature_algorithm": "1.2.840.10045.4.3.2",
            "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
            "leaf_certificate_sha256": fp_of(pf.der(leaf)),
            "initial_policies": [ANY],
            "trust_anchors": [fp_of(pf.der(root))]})


def _root(key, cn="R"):
    return pf.build_cert(cn, None, key, key, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"),
                         policies=[ANY], self_signed=True)


def _decoy_cas(n, issuer_cert, issuer_key, cn="Target CA"):
    """Same subject DN as the real CA, fresh key/SKI each time."""
    out = []
    for _ in range(n):
        dk = pf.gen_key()
        out.append(pf.build_cert(cn, issuer_cert, dk, issuer_key,
                                 is_ca=True,
                                 key_usage=("keyCertSign", "cRLSign"),
                                 policies=[ANY]))
    return out


# --------------------------------------------------------------- unit
def test_identity_rule_pure():
    a, b = "aa", "bb"
    # No AKI: everything name-compatible.
    assert identity_compatible(None, b, "k1", frozenset())
    # Issuer without SKI is always retained (compatibility).
    assert identity_compatible(a, None, "k1", frozenset())
    # SKI match.
    assert identity_compatible(a, a, "k1", frozenset({a}))
    # SKI mismatch, different key -> reject.
    assert not identity_compatible(a, b, "kX", frozenset({"k1"}))
    # SKI mismatch but SAME key as the AKI's SKI owner -> cross-sign kept.
    assert identity_compatible(a, b, "k1", frozenset({"k1"}))


# -------------------------------------------------- 256 decoy scenario
def test_aki_prefilters_same_subject_decoys_constant_parse(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = _root(rk, "Target Root")
    ca = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("target.leaf", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("target.leaf",))
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=2)
    decoys = _decoy_cas(256, root, rk)
    for c in (root, ca, leaf, *decoys):
        h.add_cert(c)
    h.add_crl(crl, 0)
    h.add_crl(rcrl, 1)
    h.seal()

    res = h.judge(leaf, root, lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    assert res["verdict"]["selected_path"] == [
        fp_of(pf.der(leaf)), fp_of(pf.der(ca)), fp_of(pf.der(root))]
    # Only root, the real CA and the leaf are ever fully parsed; the 256
    # AKI-mismatched same-subject decoys cost zero full parses.
    assert res["path_search"]["certificates_fully_parsed"] == 3
    explored_parents = {e["parent"]
                        for e in res["path_search"]["explored_edges"]}
    decoy_fps = {fp_of(pf.der(d)) for d in decoys}
    assert not (explored_parents & decoy_fps)


def test_parse_count_does_not_grow_with_decoy_count(tmp_path):
    """The same adjudication at two decoy population levels parses the same
    number of certificates (linear -> constant regression guard)."""
    counts = {}
    for n in (0, 256):
        h = Harness(tmp_path / f"n{n}")
        rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
        root = _root(rk)
        ca = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"),
                           policies=[ANY])
        leaf = pf.build_cert("target.leaf", ca, lk, ck,
                             key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY])
        for c in (root, ca, leaf, *_decoy_cas(n, root, rk)):
            h.add_cert(c)
        h.add_crl(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                               next_update=SIGNED + 100, crl_number=1), 0)
        h.add_crl(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                               next_update=SIGNED + 100, crl_number=1), 1)
        h.seal()
        res = h.judge(leaf, root, lk)
        assert res["verdict"]["status"] == "VALID"
        counts[n] = res["path_search"]["certificates_fully_parsed"]
    assert counts[0] == counts[256] == 3


# ------------------------------------------------------------- no AKI
def test_leaf_without_aki_examines_full_same_name_bucket(tmp_path):
    """No AKI: a same-subject CA whose key is NOT referenced by any SKI is
    still reached — the whole same-name candidate set is considered."""
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = _root(rk)
    ca = pf.build_cert("Shared CA Name", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    # Decoys same subject, different keys/SKIs: without an AKI every one is a
    # candidate (and gets a full parse); the real signature still selects ca.
    decoys = _decoy_cas(8, root, rk, cn="Shared CA Name")
    leaf = pf.build_cert("leaf", ca, lk, ck, no_aki=True,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    for c in (root, ca, leaf, *decoys):
        h.add_cert(c)
    h.add_crl(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 0)
    h.add_crl(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 1)
    h.seal()
    res = h.judge(leaf, root, lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    # Every same-name CA (real + decoys) was parsed: no-AKI keeps full scope.
    assert res["path_search"]["certificates_fully_parsed"] >= 1 + 1 + 1 + 8

    # Offline recomputation (decoys bundled as explored edges) agrees.
    import json as _json
    set_manifest = _json.loads(h.store.get_set(h.sid)["manifest_json"])
    pkg_path = os.path.join(h.tmp, "noaki.zip")
    with open(pkg_path, "wb") as f:
        f.write(build_package(h.store, res, set_manifest))
    assert verify_package(pkg_path)["ok"]


# ----------------------------------------------------- issuer no SKI
def test_issuer_without_ski_is_retained(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = _root(rk)
    # Real CA has NO subjectKeyIdentifier. The leaf's method-1 AKI
    # (SHA-1 of the key) cannot name an SKI; the no-SKI candidate must be
    # retained rather than filtered.
    ca = pf.build_cert("Legacy CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"),
                       policies=[ANY], no_ski=True)
    leaf = pf.build_cert("leaf", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    decoys = _decoy_cas(16, root, rk, cn="Legacy CA")
    for c in (root, ca, leaf, *decoys):
        h.add_cert(c)
    # CRL issued by the no-SKI CA; CRL signer resolution must reach it too.
    h.add_crl(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 0)
    h.add_crl(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 1)
    h.seal()
    res = h.judge(leaf, root, lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    assert res["verdict"]["selected_path"][1] == fp_of(pf.der(ca))
    assert res["revocation_results"][0]["conclusion"] == "GOOD"

    # Offline recomputation must resolve the no-SKI CRL signer identically.
    import json as _json
    set_manifest = _json.loads(h.store.get_set(h.sid)["manifest_json"])
    pkg_path = os.path.join(h.tmp, "noski.zip")
    with open(pkg_path, "wb") as f:
        f.write(build_package(h.store, res, set_manifest))
    report = verify_package(pkg_path)
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]


# ------------------------------------------------- same-key cross-sign
def test_same_key_cross_sign_with_different_ski_is_kept(tmp_path):
    """Two CA certificates share subject DN and public key but carry
    different SKIs; the leaf's AKI names one of them. The path to the anchor
    exists only through the other SKI variant — it must survive prefiltering.
    """
    h = Harness(tmp_path)
    r1k, r2k, cak, lk = (pf.gen_key() for _ in range(4))
    root1 = _root(r1k, "R1")
    root2 = _root(r2k, "R2")
    # ca1 under R1 keeps the default (method-1) SKI S_A; ca2 under R2 shares
    # the same key but presents a different SKI S_B.
    ca1 = pf.build_cert("Cross CA", root1, cak, r1k, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    from app.certmodel import parse_certificate as _pc
    s_a = _pc(pf.der(ca1)).ski
    s_b = bytes([(s_a[0] ^ 0xFF)]) + s_a[1:]
    ca2 = pf.build_cert("Cross CA", root2, cak, r2k, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"),
                        policies=[ANY], ski_override=s_b)
    # Leaf explicitly references the S_A SKI.
    leaf = pf.build_cert("leaf", ca1, lk, cak,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         issuer_ski_override=s_a)
    # Same-subject decoys with unrelated keys/SKIs.
    decoys = _decoy_cas(32, root1, r1k, cn="Cross CA")
    for c in (root1, root2, ca1, ca2, leaf, *decoys):
        h.add_cert(c)
    h.add_crl(pf.build_crl(ca2, cak, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 0)
    h.add_crl(pf.build_crl(root2, r2k, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 1)
    h.seal()
    # Anchor R2: only leaf -> ca2 (same key, different SKI) -> R2 exists.
    res = h.judge(leaf, root2, lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    assert res["verdict"]["selected_path"] == [
        fp_of(pf.der(leaf)), fp_of(pf.der(ca2)), fp_of(pf.der(root2))]

    # Offline recomputation sees only path/edge-referenced certs (the 32
    # unrelated decoys are not bundled); the same-key target (ca1) IS an
    # explored node, so resolution must stay identical byte-for-byte.
    manifest = h.store.get_set(h.sid)
    import json as _json
    set_manifest = _json.loads(manifest["manifest_json"])
    pkg_path = os.path.join(h.tmp, "cross.zip")
    with open(pkg_path, "wb") as f:
        f.write(build_package(h.store, res, set_manifest))
    report = verify_package(pkg_path)
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]


def test_same_key_cross_sign_without_ski_is_kept(tmp_path):
    """Same-key cross-sign that omits SKI entirely must remain a candidate."""
    h = Harness(tmp_path)
    r1k, r2k, cak, lk = (pf.gen_key() for _ in range(4))
    root1 = _root(r1k, "R1")
    root2 = _root(r2k, "R2")
    ca1 = pf.build_cert("Cross CA", root1, cak, r1k, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    from app.certmodel import parse_certificate as _pc
    s_a = _pc(pf.der(ca1)).ski
    ca2 = pf.build_cert("Cross CA", root2, cak, r2k, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"),
                        policies=[ANY], no_ski=True)
    leaf = pf.build_cert("leaf", ca1, lk, cak,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         issuer_ski_override=s_a)
    for c in (root1, root2, ca1, ca2, leaf):
        h.add_cert(c)
    h.add_crl(pf.build_crl(ca2, cak, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 0)
    h.add_crl(pf.build_crl(root2, r2k, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 1)
    h.seal()
    res = h.judge(leaf, root2, lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    assert res["verdict"]["selected_path"][1] == fp_of(pf.der(ca2))


# --------------------------------------------------------- legacy data
def test_legacy_name_only_sidecar_remains_usable(tmp_path):
    """Sealed data with only the v1 name-only sidecar stays adjudicable."""
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = _root(rk)
    ca = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("leaf", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    decoys = _decoy_cas(8, root, rk)
    for c in (root, ca, leaf, *decoys):
        h.add_cert(c)
    h.add_crl(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 0)
    h.add_crl(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 1)
    h.seal()
    # Emulate an archive sealed by an older build: remove the v2 sidecar and
    # rewrite nameindex.json as a name -> [digest] map.
    pkg_dir = os.path.join(h.store.root, "packages")
    os.remove(os.path.join(pkg_dir, f"{h.sid}.identity.v2.json"))
    v1_path = os.path.join(pkg_dir, f"{h.sid}.nameindex.json")
    v1 = json.load(open(v1_path))
    # current writer already emits v1 shape; double-check and rewrite plainly
    assert all(isinstance(v, list) for v in v1.values())
    with open(v1_path, "w") as f:
        f.write(canonical.dumps({k: [e["d"] if isinstance(e, dict) else e
                                     for e in v]
                                 for k, v in v1.items()}).decode())
    res = h.judge(leaf, root, lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]


def test_sealed_set_without_any_sidecar_remains_usable(tmp_path):
    """Oldest archive form: no index sidecar at all; the slow full-scan
    fallback still produces the verdict."""
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = _root(rk)
    ca = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("leaf", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_crl(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 0)
    h.add_crl(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 1)
    h.seal()
    pkg_dir = os.path.join(h.store.root, "packages")
    os.remove(os.path.join(pkg_dir, f"{h.sid}.identity.v2.json"))
    os.remove(os.path.join(pkg_dir, f"{h.sid}.nameindex.json"))
    res = h.judge(leaf, root, lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]


# ---------------------------- restart: online/offline consistent bytes
def test_restart_byte_identical_and_offline_verifier(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = _root(rk)
    ca = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("target.leaf", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("target.leaf",))
    decoys = _decoy_cas(256, root, rk)
    for c in (root, ca, leaf, *decoys):
        h.add_cert(c)
    h.add_crl(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 0)
    h.add_crl(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1), 1)
    manifest = h.seal()
    d = hashlib.sha256(b"artifact").digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    raw_req = {
        "artifact_digest": d.hex(), "signature": s.hex(),
        "signature_algorithm": "1.2.840.10045.4.3.2",
        "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(leaf)),
        "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]}
    res1 = adjudicate(h.store, h.sid, raw_req)
    assert res1["verdict"]["status"] == "VALID"

    # Simulate a process restart / instance switch: a fresh Store over the
    # same persisted volume replays the IDENTICAL request byte-identically.
    store2 = Store(os.path.join(h.tmp, "data"))
    res2 = adjudicate(store2, h.sid, raw_req)
    assert canonical.dumps(res2) == canonical.dumps(res1)

    # ... and a cold core recomputation (bypassing the adjudication cache)
    # reaches the same verdict with the same constant parse footprint.
    from app.adjudge import normalize_request, run_core
    import json as _json
    set_row = store2.get_set(h.sid)
    manifest2 = _json.loads(set_row["manifest_json"])
    loaded2 = LoadedSet.from_store(store2, manifest2)
    res3 = run_core(loaded2, manifest2, normalize_request(raw_req))
    assert res3["verdict"]["status"] == "VALID"
    assert canonical.dumps(res3) == canonical.dumps(res1)
    assert loaded2.full_parse_count == 3

    # The offline verifier rebuilds the graph purely from packaged DER and
    # re-runs the same core; byte-for-byte agreement is required.
    pkg = build_package(h.store, res1, manifest)
    pkg_path = os.path.join(h.tmp, "pkg.zip")
    with open(pkg_path, "wb") as f:
        f.write(pkg)
    report = verify_package(pkg_path)
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
