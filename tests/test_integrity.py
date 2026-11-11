import dataclasses
import unittest

from dmf_integrity import (
    AuditChain, ModuleRef, Mutability, build_version, canonicalize, check_restrictions,
    content_sha256, make_checkpoint, manifest_root, module_proof, risk_floor,
    three_way_merge, verify_chain, verify_checkpoint, verify_version_chain,
)
from dmf_integrity.audit_chain import ChainBrokenError, HmacDevSigner
from dmf_integrity.canonical import CanonicalizationError
from dmf_integrity.merkle import inclusion_proof, leaf_hash, merkle_root, verify_inclusion

M, R, C = Mutability.MUTABLE, Mutability.RESTRICTED, Mutability.IMMUTABLE_CORE


def mod(mid, ordinal, text, mut=M, deps=()):
    return ModuleRef(mid, "section", mut, ordinal, content_sha256(text.encode()), tuple(deps))


BASE = (
    mod("core.rules", 0, "Rule 1: never delete audit data", C),
    mod("sec.intro", 1, "Intro v1"),
    mod("sec.scope", 2, "Scope v1", R, deps=["core.rules"]),
    mod("sec.body", 3, "Body v1", deps=["sec.scope"]),
)


class CanonicalTest(unittest.TestCase):
    def test_key_order_and_whitespace(self):
        self.assertEqual(canonicalize({"b": 1, "a": [True, None, "x"]}),
                         b'{"a":[true,null,"x"],"b":1}')

    def test_unicode_literal_and_control_escape(self):
        self.assertEqual(canonicalize({"k": "문서\n\x01"}), '{"k":"문서\\n\\u0001"}'.encode())

    def test_float_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize({"x": 1.5})


class MerkleTest(unittest.TestCase):
    def test_inclusion_proofs_all_sizes(self):
        for n in range(1, 34):
            leaves = [leaf_hash(str(i).encode()) for i in range(n)]
            root = merkle_root(leaves)
            for i in range(n):
                p = inclusion_proof(leaves, i)
                self.assertTrue(verify_inclusion(leaves[i], i, n, p, root), (n, i))
                if n > 1:
                    self.assertFalse(verify_inclusion(leaves[i], (i + 1) % n, n, p, root))

    def test_domain_separation(self):
        a, b = leaf_hash(b"a"), leaf_hash(b"b")
        # An interior node can't be replayed as a 1-leaf tree with the same root.
        self.assertNotEqual(merkle_root([a, b]), leaf_hash(a + b))


class VersionTest(unittest.TestCase):
    def test_module_proof(self):
        root = bytes.fromhex(manifest_root(BASE))
        idx, size, path = module_proof(BASE, "sec.scope")
        target = next(m for m in BASE if m.module_id == "sec.scope")
        self.assertTrue(verify_inclusion(target.leaf(), idx, size, [bytes.fromhex(h) for h in path], root))

    def test_chain_and_rollback(self):
        meta = {"dc:title": "Policy", "dc:creator": "urn:dmf:agent:alice"}
        v1 = build_version("doc-1", 1, None, BASE, meta)
        edited = tuple(mod("sec.body", 3, "Body v2", deps=["sec.scope"]) if m.module_id == "sec.body" else m
                       for m in BASE)
        v2 = build_version("doc-1", 2, v1, edited, meta)
        v3 = build_version("doc-1", 3, v2, v1.modules, meta)   # rollback == roll-forward to v1 content
        verify_version_chain([v1, v2, v3])
        self.assertEqual(v3.manifest_root, v1.manifest_root)   # same content identity
        self.assertNotEqual(v3.version_hash, v1.version_hash)  # distinct history identity

        tampered = dataclasses.replace(v2, metadata={**meta, "dc:title": "Hacked"})
        with self.assertRaises(ValueError):
            verify_version_chain([v1, tampered, v3])


class RestrictTest(unittest.TestCase):
    def test_core_modification_blocked(self):
        cand = tuple(mod("core.rules", 0, "Rule 1: delete whatever", C) if m.module_id == "core.rules" else m
                     for m in BASE)
        codes = {v.code for v in check_restrictions(BASE, cand)}
        self.assertIn("CORE_MODIFIED", codes)
        self.assertEqual(check_restrictions(BASE, cand, allow_core_amendment=True), [])
        self.assertEqual(risk_floor(BASE, cand), 3)

    def test_reordering_mutable_keeps_seal(self):
        cand = tuple(dataclasses.replace(m, ordinal=10 - m.ordinal) if m.mutability is M else m for m in BASE)
        self.assertEqual(check_restrictions(BASE, cand), [])

    def test_dangling_dependency_and_cycle(self):
        cand = tuple(m for m in BASE if m.module_id != "sec.scope")
        self.assertIn("DANGLING_DEPENDENCY", {v.code for v in check_restrictions(BASE, cand)})
        cyc = BASE[:3] + (mod("sec.body", 3, "Body v1", deps=["sec.scope"]),
                          mod("sec.x", 4, "x", deps=["sec.y"]), mod("sec.y", 5, "y", deps=["sec.x"]))
        self.assertIn("DEPENDENCY_CYCLE", {v.code for v in check_restrictions(BASE, cyc)})

    def test_risk_levels(self):
        self.assertEqual(risk_floor(BASE, BASE), 0)
        intro = tuple(mod("sec.intro", 1, "Intro v2") if m.module_id == "sec.intro" else m for m in BASE)
        self.assertEqual(risk_floor(BASE, intro), 1)
        scope = tuple(mod("sec.scope", 2, "Scope v2", R, ["core.rules"]) if m.module_id == "sec.scope" else m
                      for m in BASE)
        self.assertEqual(risk_floor(BASE, scope), 2)


class MergeTest(unittest.TestCase):
    def test_disjoint_edits_merge_cleanly(self):
        ours = tuple(mod("sec.intro", 1, "Intro A") if m.module_id == "sec.intro" else m for m in BASE)
        theirs = tuple(mod("sec.body", 3, "Body B", deps=["sec.scope"]) if m.module_id == "sec.body" else m
                       for m in BASE)
        r = three_way_merge(BASE, ours, theirs)
        self.assertTrue(r.clean)
        self.assertEqual({m.module_id: m for m in r.modules}["sec.intro"].content_sha256,
                         content_sha256(b"Intro A"))

    def test_same_module_conflicts(self):
        ours = tuple(mod("sec.intro", 1, "Intro A") if m.module_id == "sec.intro" else m for m in BASE)
        theirs = tuple(mod("sec.intro", 1, "Intro B") if m.module_id == "sec.intro" else m for m in BASE)
        r = three_way_merge(BASE, ours, theirs)
        self.assertEqual([c.module_id for c in r.conflicts], ["sec.intro"])

    def test_insert_same_ordinal_conflicts(self):
        r = three_way_merge(BASE, BASE + (mod("sec.a", 9, "a"),), BASE + (mod("sec.b", 9, "b"),))
        self.assertFalse(r.clean)


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.chain = AuditChain("urn:dmf:doc:doc-1")
        for i, action in enumerate(["ticket.open", "version.commit", "ticket.approve"]):
            self.chain.append(occurred_at=f"2026-11-11T00:00:0{i}.000000Z", actor="urn:dmf:agent:alice",
                              action=action, target="urn:dmf:doc:doc-1", ticket_id="T-1", detail={"i": i})

    def test_valid_chain(self):
        verify_chain(self.chain.entries)

    def test_tamper_detected(self):
        es = list(self.chain.entries)
        es[1] = dataclasses.replace(es[1], actor="urn:dmf:agent:mallory")
        with self.assertRaises(ChainBrokenError) as cm:
            verify_chain(es)
        self.assertEqual(cm.exception.seq, 2)

    def test_deletion_and_truncation_detected(self):
        with self.assertRaises(ChainBrokenError):
            verify_chain([self.chain.entries[0], self.chain.entries[2]])
        with self.assertRaises(ChainBrokenError):
            verify_chain(self.chain.entries[:2], expected_head=self.chain.head)

    def test_checkpoint(self):
        signer = HmacDevSigner("dev-1", b"secret")
        other = AuditChain("urn:dmf:doc:doc-2")
        other.append(occurred_at="2026-11-11T00:00:00.000000Z", actor="a", action="x", target="t")
        cp = make_checkpoint("tenant-a", 1, "0" * 64, "2026-11-11T01:00:00Z", [self.chain, other], signer)
        self.assertTrue(verify_checkpoint(cp, signer))
        forged = dataclasses.replace(cp, heads=(("urn:dmf:doc:doc-1", 3, "f" * 64),) + cp.heads[1:])
        self.assertFalse(verify_checkpoint(forged, signer))


if __name__ == "__main__":
    unittest.main()
