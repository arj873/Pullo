"""BENCH-ANCESTRY-01: generic verified base-ancestor proof from REAL local Git commit objects. No network, no real data."""

from __future__ import annotations

import base64
import copy
import subprocess
import tempfile
import unittest
from pathlib import Path

from reviewer.pilot import benchmark as B
from reviewer.pilot.ancestry import AncestryError, SCHEMA, check_endpoints, verify_chain
from tests.pilot.test_benchmark_host import Base, BWorld
from tests.repoimport.helpers import git


def raw(repo: Path, oid: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), "cat-file", "commit", oid], check=True, capture_output=True).stdout


def entry(repo, oid):
    return {"oid": oid, "rawBase64": base64.b64encode(raw(repo, oid)).decode()}


def proof(repo, oids):
    return {"schema": SCHEMA, "commits": [entry(repo, o) for o in oids]}


def commit(repo: Path, name: str, *, merge=None) -> str:
    (repo / name).write_text(name)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", name, "--no-verify")
    return git(repo, "rev-parse", "HEAD")


class ChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._t = tempfile.TemporaryDirectory()
        r = cls.r = Path(cls._t.name)
        git(r, "init", "-q", "--initial-branch=main")
        cls.c0 = commit(r, "a")
        cls.c1 = commit(r, "b")
        cls.c2 = commit(r, "c")
        cls.c3 = commit(r, "d")
        git(r, "checkout", "-q", "-b", "side", cls.c1)
        cls.s1 = commit(r, "s")
        git(r, "checkout", "-q", "main")
        git(r, "merge", "-q", "--no-ff", "-m", "merge", "side")      # merge: parents [c3, s1]
        cls.m = git(r, "rev-parse", "HEAD")
        git(r, "checkout", "-q", "-b", "other", cls.c0)
        cls.u = commit(r, "unrelated-branch")

    @classmethod
    def tearDownClass(cls):
        cls._t.cleanup()

    def ok(self, oids):
        return verify_chain(proof(self.r, oids), oids[0], oids[-1])

    def bad(self, p, head, base, word=""):
        with self.assertRaises(AncestryError) as c:
            verify_chain(p, head, base)
        self.assertIn(word, str(c.exception))

    def test_linear_three_and_more_commits(self):
        self.assertEqual([c[0] for c in self.ok([self.c3, self.c2, self.c1])], [self.c3, self.c2, self.c1])
        self.assertEqual(len(self.ok([self.c3, self.c2, self.c1, self.c0])), 4)
        self.assertEqual(len(self.ok([self.c1, self.c0])), 2)

    def test_merge_either_parent_is_a_valid_path(self):
        self.ok([self.m, self.c3])                 # first parent
        self.ok([self.m, self.s1])                 # second parent
        self.ok([self.m, self.s1, self.c1])        # through the side branch
        self.ok([self.m, self.c3, self.c2, self.c1])

    def test_unrelated_or_non_link_or_reordered_or_skipped(self):
        self.bad(proof(self.r, [self.c3, self.u]), self.c3, self.u, "not a parent")
        self.bad(proof(self.r, [self.c3, self.c1]), self.c3, self.c1, "not a parent")            # skipped c2
        self.bad(proof(self.r, [self.c1, self.c2, self.c3]), self.c1, self.c3, "not a parent")   # reordered
        self.bad(proof(self.r, [self.c3, self.c2, self.c1]), self.c3, self.c0, "end at")
        self.bad(proof(self.r, [self.c3, self.c2, self.c1]), self.c2, self.c1, "start at")

    def test_duplicate_and_bounds(self):
        p = proof(self.r, [self.c3, self.c2, self.c3])
        self.bad(p, self.c3, self.c3, "repeats")
        self.bad(proof(self.r, [self.c3]), self.c3, self.c3, "commits must be")
        self.bad({"schema": SCHEMA, "commits": []}, self.c3, self.c2, "commits must be")
        big = {"schema": SCHEMA, "commits": [entry(self.r, self.c3)] * 1025}
        self.bad(big, self.c3, self.c3, "commits must be")

    def test_tampered_raw_wrong_oid_and_type(self):
        p = proof(self.r, [self.c3, self.c2])
        t = copy.deepcopy(p)
        b = bytearray(base64.b64decode(t["commits"][1]["rawBase64"]))
        b[-2] ^= 1
        t["commits"][1]["rawBase64"] = base64.b64encode(bytes(b)).decode()
        self.bad(t, self.c3, self.c2, "do not hash")
        w = copy.deepcopy(p)
        w["commits"][1]["oid"] = self.c1
        self.bad(w, self.c3, self.c1, "do not hash")
        for key, val in (("oid", "XYZ"), ("oid", self.c2.upper()), ("oid", 5), ("rawBase64", 5)):
            x = copy.deepcopy(p)
            x["commits"][1][key] = val
            self.bad(x, self.c3, self.c2)
        tree = subprocess.run(["git", "-C", str(self.r), "cat-file", "tree", self.c2 + "^{tree}"], check=True,
                              capture_output=True).stdout
        notcommit = copy.deepcopy(p)
        notcommit["commits"][1]["rawBase64"] = base64.b64encode(tree).decode()
        self.bad(notcommit, self.c3, self.c2)

    def test_base64_strictness_and_caps(self):
        p = proof(self.r, [self.c3, self.c2])
        for bad in (p["commits"][1]["rawBase64"] + "\n", p["commits"][1]["rawBase64"][:-1], "!!!!", " " + p["commits"][1]["rawBase64"]):
            x = copy.deepcopy(p)
            x["commits"][1]["rawBase64"] = bad
            self.bad(x, self.c3, self.c2)
        x = copy.deepcopy(p)
        x["commits"][1]["rawBase64"] = base64.b64encode(b"a" * 70000).decode()
        self.bad(x, self.c3, self.c2, "cap")

    def test_shape_and_extra_keys(self):
        p = proof(self.r, [self.c3, self.c2])
        for mut in (lambda d: d.update(extra=1), lambda d: d.update(schema="benchmark-ancestry@2"),
                    lambda d: d["commits"][0].update(message="x"), lambda d: d.pop("schema")):
            x = copy.deepcopy(p)
            mut(x)
            self.bad(x, self.c3, self.c2)
        for junk in (None, [], "x", 3):
            self.bad(junk, self.c3, self.c2)

    def test_endpoint_record_binding(self):
        chain = self.ok([self.c3, self.c2])
        head = {"commitSha": chain[0][0], "treeOid": chain[0][1], "parents": chain[0][2]}
        base = {"commitSha": chain[1][0], "treeOid": chain[1][1], "parents": chain[1][2]}
        check_endpoints(chain, head, base)
        for name, h, b in (("tree", {**head, "treeOid": "0" * 40}, base), ("parents", head, {**base, "parents": []}),
                           ("commit", {**head, "commitSha": self.c1}, base)):
            with self.assertRaises(AncestryError, msg=name):
                check_endpoints(chain, h, b)


def decision_with(w, *, proof_obj, drop=("originalHeadSoleParentIsBase",), **extra):
    d = {k: v for k, v in w.decision.items() if k not in drop}
    d.update({"mergeBaseAncestryVerified": True, "ancestryProof": proof_obj}, **extra)
    return d


class IngestTests(Base):
    def chain(self, w=None):
        w = w or self.w
        return proof(w.src, [w.sha["head"], w.base_sha])

    def test_new_mode_plans_and_binds_the_chain_into_decision_identity(self):
        before = self.plan()
        self.rewrite(decision=decision_with(self.w, proof_obj=self.chain()))
        after = self.plan()
        self.assertEqual(after["status"], before["status"])
        self.assertNotEqual(before["launchBaselineDigest"], after["launchBaselineDigest"])

    def test_new_mode_refusals_happen_before_key_and_output(self):
        good = self.chain()
        t = copy.deepcopy(good)
        t["commits"][0]["rawBase64"] = t["commits"][0]["rawBase64"][:-4] + "AAAA"
        cases = {
            "tampered": decision_with(self.w, proof_obj=t),
            "wrong end": decision_with(self.w, proof_obj={**good, "commits": good["commits"][::-1]}),
            "legacy flag present": decision_with(self.w, proof_obj=good, drop=(), originalHeadSoleParentIsBase=True),
            "ancestry unconfirmed": {**decision_with(self.w, proof_obj=good), "mergeBaseAncestryVerified": "true"},
            "no proof": {k: v for k, v in decision_with(self.w, proof_obj=good).items() if k != "ancestryProof"},
            "flag without legacy": {k: v for k, v in self.w.decision.items() if k != "originalHeadSoleParentIsBase"},
        }
        for name, d in cases.items():
            with self.subTest(name):
                self.rewrite(decision=d)
                self.refused()

    def test_chain_for_other_commits_is_refused_against_imports(self):
        w = self.w
        other = proof(w.src, [w.sha["head"], w.base_sha])
        other["commits"][1] = {"oid": w.sha["head"], "rawBase64": other["commits"][0]["rawBase64"]}
        self.rewrite(decision=decision_with(w, proof_obj=other))
        self.refused()

    def test_legacy_mode_is_unchanged(self):
        self.plan()
        self.rewrite(decision={**self.w.decision, "originalHeadSoleParentIsBase": False})
        self.refused()
        self.assertIn("originalHeadSoleParentIsBase", B.DECISION_TRUE)


if __name__ == "__main__":
    unittest.main()
