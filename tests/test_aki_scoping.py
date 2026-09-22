"""AKI-scoped issuer resolution.

When a certificate carries an AKI keyIdentifier, same-subject certificates
with a different, present SKI are provably not name/key-compatible and must
never be fully parsed: full-parse work stays constant as same-subject decoys
are added. The fallback cases must keep working identically:

* no AKI on the child -> the whole same-name candidate set is examined;
* issuer certificate without an SKI extension -> retained for compatibility;
* same-key cross-signed certificates (different SKI) -> never pruned;
* archives sealed with the v1 name-only index -> full-bucket fallback;
* online adjudication and offline package re-verification agree byte-for-byte
  after a "restart" (fresh store handle on the same data directory).
"""
import hashlib
import io
import json
import os
import sys
import zipfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.adjudge import adjudicate
from app.certmodel import fp_of
from app.package import build_package
from app.storage import Store
from verify.verify_package import verify_package

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


def _chain():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("Target Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("target.leaf", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("target.leaf",))
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    return rk, ck, lk, root, ca, leaf, crl, rcrl


def _decoy_rows(store, n):
    """n self-signed CAs with the exact subject DN of the real Target CA but
    distinct keys (hence distinct SKIs)."""
    rows = []
    for i in range(n):
        dk = pf.gen_key()
        decoy = pf.build_cert("Target CA", None, dk, dk, is_ca=True,
                              key_usage=("keyCertSign", "cRLSign"),
                              policies=[ANY], self_signed=True)
        d = pf.der(decoy)
        store.put_blob(d)
        rows.append({"client_ref": f"decoy{i:04d}", "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    return rows


def _cert_rows(store, certs):
    rows = []
    for c in certs:
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": "c" + fp_of(d)[:12], "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    return rows


def _crl_rows(store, crls):
    rows = []
    for i, c in enumerate(crls):
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": f"r{i}", "kind": "crl",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    return rows


def _judge(store, sid, leaf, lk, root):
    d = hashlib.sha256(b"artifact").digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    return adjudicate(store, sid, {
        "artifact_digest": d.hex(), "signature": s.hex(),
        "signature_algorithm": "1.2.840.10045.4.3.2",
        "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(leaf)),
        "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]})


def test_aki_scoped_parse_count_constant_with_same_subject_decoys(tmp_path):
    """The 256-decoy acceptance scenario: VALID and only root/CA/leaf parsed,
    at both small and large decoy populations."""
    counts = {}
    saved = None
    for n in (0, 16, 256):
        store = Store(str(tmp_path / f"data{n}"))
        sid = f"es_aki_const_{n:032d}"
        store.create_set(sid, "c")
        rk, ck, lk, root, ca, leaf, crl, rcrl = _chain()
        rows = _cert_rows(store, (root, ca, leaf))
        rows += _decoy_rows(store, n)
        rows += _crl_rows(store, (crl, rcrl))
        store.add_items(sid, rows)
        store.seal(sid)
        result = _judge(store, sid, leaf, lk, root)
        assert result["verdict"]["status"] == "VALID", result["verdict"]
        counts[n] = result["processing"]["certs_fully_parsed"]
        if n == 256:
            saved = (store, sid, root, ca, leaf, lk, result)
        else:
            store.close()
    assert counts == {0: 3, 16: 3, 256: 3}, counts
    # The AKI-mismatched decoys never appear in the parsed certificate list.
    store, sid, root, ca, leaf, lk, result = saved
    parsed = set(result["processing"]["certificates"])
    assert parsed == {fp_of(pf.der(root)), fp_of(pf.der(ca)),
                      fp_of(pf.der(leaf))}
    store.close()


def test_leaf_without_aki_examines_full_same_name_set(tmp_path):
    """No AKI: the complete same-name candidate set must still be checked."""
    store = Store(str(tmp_path / "data"))
    sid = "es_noaki_000000000000000000000000001"
    store.create_set(sid, "c")
    rk, ck, lk, root, ca, _, crl, rcrl = _chain()
    leaf_no_aki = pf.build_cert("target.leaf", ca, lk, ck,
                                key_usage=("digitalSignature",),
                                eku=("codeSigning",), policies=[ANY],
                                add_aki=False)
    n = 64
    rows = _cert_rows(store, (root, ca, leaf_no_aki))
    rows += _decoy_rows(store, n)
    rows += _crl_rows(store, (crl, rcrl))
    store.add_items(sid, rows)
    store.seal(sid)
    result = _judge(store, sid, leaf_no_aki, lk, root)
    assert result["verdict"]["status"] == "VALID", result["verdict"]
    # Every same-name CA (real + n decoys) is parsed without an AKI to scope.
    assert result["processing"]["certs_fully_parsed"] == 3 + n


def test_issuer_without_ski_is_retained(tmp_path):
    """Issuer CA carrying no SKI extension stays a candidate even when the
    child has an AKI (RFC 5280 compatibility)."""
    store = Store(str(tmp_path / "data"))
    sid = "es_noski_000000000000000000000000001"
    store.create_set(sid, "c")
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("Target Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca_noski = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY], add_ski=False)
    leaf = pf.build_cert("target.leaf", ca_noski, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    # CRL without AKI, signed by the SKI-less CA.
    crl = pf.build_crl(ca_noski, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1, akify=False)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    rows = _cert_rows(store, (root, ca_noski, leaf))
    rows += _decoy_rows(store, 32)
    rows += _crl_rows(store, (crl, rcrl))
    store.add_items(sid, rows)
    store.seal(sid)
    result = _judge(store, sid, leaf, lk, root)
    assert result["verdict"]["status"] == "VALID", result["verdict"]
    parsed = set(result["processing"]["certificates"])
    assert fp_of(pf.der(ca_noski)) in parsed
    # SKI-present AKI-mismatched decoys are still pruned.
    assert result["processing"]["certs_fully_parsed"] == 3


def test_same_key_cross_sign_with_different_ski_is_not_pruned(tmp_path):
    """Two issuer certs with the SAME subject DN and public key but different
    SKI extensions (a cross-sign): the leaf's AKI matches only one SKI, yet
    the key-sharing cross cert must be reachable for the alt anchor path."""
    store = Store(str(tmp_path / "data"))
    sid = "es_xsign_000000000000000000000000001"
    store.create_set(sid, "c")
    r1k, r2k, cak, lk = pf.gen_key(), pf.gen_key(), pf.gen_key(), pf.gen_key()
    r1 = pf.build_cert("R1", None, r1k, r1k, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       self_signed=True)
    r2 = pf.build_cert("R2", None, r2k, r2k, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       self_signed=True)
    # ca_by_r1: SKI derived from the shared key (what the leaf AKI cites).
    ca_by_r1 = pf.build_cert("Shared CA", r1, cak, r1k, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY])
    # ca_by_r2: same subject and same key, but a deliberately different SKI.
    other_ski = bytes(range(20))
    ca_by_r2 = pf.build_cert("Shared CA", r2, cak, r2k, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY], ski_override=other_ski)
    leaf = pf.build_cert("codesign", ca_by_r1, lk, cak,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("codesign.test",))
    crl_r1 = pf.build_crl(r1, r1k, [], last_update=SIGNED - 100,
                          next_update=SIGNED + 100, crl_number=1)
    crl_r2 = pf.build_crl(r2, r2k, [], last_update=SIGNED - 100,
                          next_update=SIGNED + 100, crl_number=1)
    # Clearance CRL issued under the cross cert's key (covers the leaf under
    # the R2 path as well); no CRL AKI so it is compatible with both cross
    # certs' identity.
    crl_ca = pf.build_crl(ca_by_r2, cak, [], last_update=SIGNED - 100,
                          next_update=SIGNED + 100, crl_number=1,
                          akify=False)
    rows = _cert_rows(store, (r1, r2, ca_by_r1, ca_by_r2, leaf))
    rows += _crl_rows(store, (crl_r1, crl_r2, crl_ca))
    store.add_items(sid, rows)
    store.seal(sid)
    d = hashlib.sha256(b"artifact").digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    req = {
        "artifact_digest": d.hex(), "signature": s.hex(),
        "signature_algorithm": "1.2.840.10045.4.3.2",
        "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(leaf)),
        "initial_policies": [ANY]}

    res1 = adjudicate(store, sid, {**req, "trust_anchors": [fp_of(pf.der(r1))]})
    assert res1["verdict"]["status"] == "VALID"
    assert res1["verdict"]["selected_path"] == [
        fp_of(pf.der(leaf)), fp_of(pf.der(ca_by_r1)), fp_of(pf.der(r1))]

    res2 = adjudicate(store, sid, {**req, "trust_anchors": [fp_of(pf.der(r2))]})
    assert res2["verdict"]["status"] == "VALID", res2["verdict"]
    # The cross cert (non-matching SKI, same key) was parsed via key
    # expansion and completes the alt-anchor path.
    assert res2["verdict"]["selected_path"] == [
        fp_of(pf.der(leaf)), fp_of(pf.der(ca_by_r2)), fp_of(pf.der(r2))]
    parsed = set(res2["processing"]["certificates"])
    assert fp_of(pf.der(ca_by_r2)) in parsed


def test_v1_name_only_sidecar_still_supported(tmp_path):
    """An archive sealed before the identity sidecar keeps the old semantics:
    full same-name bucket is examined, verdict unchanged."""
    store = Store(str(tmp_path / "data"))
    sid = "es_v1idx_00000000000000000000000001"
    store.create_set(sid, "c")
    rk, ck, lk, root, ca, leaf, crl, rcrl = _chain()
    n = 32
    rows = _cert_rows(store, (root, ca, leaf))
    rows += _decoy_rows(store, n)
    rows += _crl_rows(store, (crl, rcrl))
    store.add_items(sid, rows)
    store.seal(sid)
    # Downgrade the sidecar to v1 (name DER b64 -> digests, no "v" field).
    idx_path = os.path.join(store.root, "packages",
                            f"{sid}.nameindex.json")
    with open(idx_path) as f:
        v2 = json.load(f)
    with open(idx_path, "w") as f:
        json.dump(v2["names"], f)

    result = _judge(store, sid, leaf, lk, root)
    assert result["verdict"]["status"] == "VALID"
    assert result["processing"]["index_version"] == 1
    assert result["processing"]["certs_fully_parsed"] == 3 + n

    # Offline re-verification must reproduce the same v1 full-bucket work.
    from app.package import build_package
    from verify.verify_package import verify_package

    sealed = store.get_set(sid)
    manifest = json.loads(sealed["manifest_json"])
    pkg = build_package(store, result, manifest)
    with zipfile.ZipFile(io.BytesIO(pkg)) as zf:
        pkg_manifest = json.loads(zf.read("package-manifest.json"))
    assert pkg_manifest["identity_index_version"] == 1
    path = tmp_path / "v1pkg.zip"
    path.write_bytes(pkg)
    report = verify_package(str(path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]


def test_restart_replay_and_offline_reverify_agree(tmp_path):
    """Fresh store handle (process restart) gives byte-identical output and
    the offline package verifier recomputes the same AKI-scoped result."""
    from app import canonical

    data_dir = str(tmp_path / "data")
    store = Store(data_dir)
    sid = "es_restart_0000000000000000000000001"
    store.create_set(sid, "c")
    rk, ck, lk, root, ca, leaf, crl, rcrl = _chain()
    rows = _cert_rows(store, (root, ca, leaf))
    rows += _decoy_rows(store, 256)
    rows += _crl_rows(store, (crl, rcrl))
    store.add_items(sid, rows)
    manifest = store.seal(sid)

    # One fixed request (deterministic signature bytes) for both processes,
    # so the second adjudication is a genuine persistence replay.
    d = hashlib.sha256(b"artifact").digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    request = {
        "artifact_digest": d.hex(), "signature": s.hex(),
        "signature_algorithm": "1.2.840.10045.4.3.2",
        "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(leaf)),
        "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]}

    result1 = adjudicate(store, sid, request)
    pkg = build_package(store, result1, manifest)
    store.close()

    store2 = Store(data_dir)
    result2 = adjudicate(store2, sid, request)
    assert canonical.dumps(result2) == canonical.dumps(result1)
    assert result2["processing"] == result1["processing"]
    assert result2["processing"]["certs_fully_parsed"] == 3
    store2.close()

    path = tmp_path / "pkg.zip"
    path.write_bytes(pkg)
    report = verify_package(str(path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    assert report["status"] == "VALID"
