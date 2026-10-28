"""BENCH-ANCESTRY-02: independent review of the generic ancestry proof. Real local Git worlds (3-commit linear history and a
merge whose base is the SECOND parent through a side branch), REAL importer/ingest/plan, fake transport/key loader. No
network, no real data. Unique commit messages carry `ancestry-canary-*`, which must never reach a model request or report."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts.canonical import digest
from reviewer.pilot import benchmark as B
from reviewer.pilot.ancestry import AncestryError, SCHEMA, verify_chain
from reviewer.repoimport import capture_import_pins, import_repository, write_import_pins
from reviewer.repoimport.fsio import force_remove
from reviewer.repoimport.remote import local_fixture_remote
from reviewer.config import resolve_config
from tests.pilot.helpers import AUTH
from tests.pilot.test_benchmark_host import AT, URL, BWorld, Base
from tests.pilot.test_repository import BASE_FILES, GITLINK, HEAD_FILES
from tests.repoimport.helpers import git

CANARY = "ancestry-canary"


def raw_of(repo: Path, oid: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), "cat-file", "commit", oid], check=True, capture_output=True).stdout


def chain_doc(repo: Path, oids) -> dict:
    return {"schema": SCHEMA, "commits": [{"oid": o, "rawBase64": base64.b64encode(raw_of(repo, o)).decode()} for o in oids]}


class HistoryWorld(BWorld):
    """BWorld with a chosen real Git history: shape `linear` (base <- mid <- head) or `merge` (head = merge(main, S2) with
    base S1 <- S2 on the side branch, so base is reached through the SECOND parent and a 3-commit path)."""

    def __init__(self, tmp: Path, shape: str):
        self.tmp, self.src, self.store = tmp, tmp / "gitsrc", tmp / "store"
        self.op = tmp / "operator"
        self.state = self.op / "state"
        for d in (self.src, self.op, self.state):
            d.mkdir(parents=True)
        git(self.src, "init", "-q", "--initial-branch=main")
        self.sha, self.path = {}, []

        def put(files, msg):
            for p, t in files.items():
                (self.src / p).parent.mkdir(parents=True, exist_ok=True)
                (self.src / p).write_text(t)
            (self.src / "data.bin").write_bytes(b"\0\1\2base")
            git(self.src, "add", "-A", "-f")
            git(self.src, "update-index", "--add", "--cacheinfo", f"160000,{GITLINK},vendor/sub")
            git(self.src, "commit", "-q", "--allow-empty", "-m", f"{msg} {CANARY}-{msg}", "--no-verify")
            return git(self.src, "rev-parse", "HEAD")

        step_b = {**BASE_FILES, "src/b.py": HEAD_FILES["src/b.py"]}
        if shape == "linear":
            base = put(BASE_FILES, "base")
            mid = put(step_b, "mid")
            head = put(HEAD_FILES, "head")
            self.path = [head, mid, base]
        else:
            put(BASE_FILES, "root")
            git(self.src, "checkout", "-q", "-b", "side")
            s1 = put(BASE_FILES, "s1")
            s2 = put(BASE_FILES, "s2")
            git(self.src, "checkout", "-q", "main")
            put(HEAD_FILES, "m1")
            git(self.src, "merge", "-q", "--no-ff", "-m", f"merge {CANARY}-merge", "side")
            head, base = git(self.src, "rev-parse", "HEAD"), s1
            self.path = [head, s2, s1]
            self.parents_of_head = git(self.src, "rev-list", "--parents", "-n1", head).split()[1:]
        self.sha = {"base": base, "head": head}
        remote = local_fixture_remote(self.src, "o", "r")
        self.imports, self.pins = {}, {}
        for side in ("base", "head"):
            imp = import_repository(remote, self.sha[side], self.store)
            self.imports[side] = imp
            self.pins[side] = self.op / f"{side}.import-pins.json"
            write_import_pins(self.pins[side], capture_import_pins(imp.dir, captured_at=AT))
        self.auth = self.op / "auth.json"
        self.auth.write_text(json.dumps(AUTH))
        os.chmod(self.auth, 0o600)
        self.env = self.op / "dot.env"
        self.env.write_text("openrouter_key=not-read-in-tests\n")
        self.out = tmp / "out"
        self.base_sha = base
        self.write_roots()

    def new_decision(self, proof_obj, *, drop=("originalHeadSoleParentIsBase",), **extra):
        d = {k: v for k, v in self.decision.items() if k not in drop}
        d.update({"mergeBaseAncestryVerified": True, "ancestryProof": proof_obj}, **extra)
        return d


class WorldCase(Base):
    shape = "linear"

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._rm)
        self.tmp = Path(os.path.realpath(self._t.name))
        self.w = HistoryWorld(self.tmp / "w", self.shape)
        self.loads = []

    def good(self):
        return chain_doc(self.w.src, self.w.path)

    def refuse_with(self, decision, word=""):
        before = self.w.state_bytes()
        self.rewrite(decision=decision)
        msg = self.refused()                      # key loader forbidden, no output directory
        self.assertEqual(before, self.w.state_bytes())
        self.assertIn(word, msg)

    def captured_plan(self):
        bodies = []
        real = B._request_facts

        def spy(req):
            bodies.append(bytes(req.body or b""))
            return real(req)

        with mock.patch.object(B, "_request_facts", spy):
            rep = self.plan()
        return rep, bodies


class Positive:
    def test_new_mode_plans_with_a_real_multi_commit_world_and_keeps_commit_messages_off_the_wire(self):
        self.assertGreaterEqual(len(self.w.path), 3)
        self.rewrite(decision=self.w.new_decision(self.good()))
        before = self.w.state_bytes()
        rep, bodies = self.captured_plan()
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True))
        self.assertEqual(rep["changedPaths"], ["src/a.py", "src/b.py"])
        self.assertTrue(bodies)
        for b in bodies:
            self.assertNotIn(CANARY.encode(), b)
        self.assertNotIn(CANARY, json.dumps(rep))
        self.assertNotIn("ancestryProof", json.dumps(rep))
        self.assertEqual(before, self.w.state_bytes())
        self.assertEqual(len(self.w.loads) if hasattr(self.w, "loads") else 0, 0)
        # the decision file really contains the canary text (inside the raw commit objects): only its sha reaches the identity
        dec_raw = self.w.decision_path.read_bytes()
        self.assertIn(CANARY, "".join(base64.b64decode(c["rawBase64"]).decode() for c in json.loads(dec_raw)["ancestryProof"]["commits"]))
        self.assertEqual(rep["origin"]["mergeBase"], self.w.sha["base"])

    def test_decision_hash_is_bound_into_identity(self):
        self.rewrite(decision=self.w.new_decision(self.good()))
        a = self.plan()
        d2 = self.w.new_decision(self.good())
        d2["note"] = "x"
        self.rewrite(decision=d2)
        b = self.plan()
        self.assertNotEqual(a["launchBaselineDigest"], b["launchBaselineDigest"])

    def test_legacy_sole_parent_decision_refused_for_this_multi_commit_world(self):
        self.refused()                                                     # legacy: head parents != [base]

    def test_new_mode_negative_matrix_refuses_before_key_state_output(self):
        good = self.good()
        mid = good["commits"]

        def mut(f):
            x = copy.deepcopy(good)
            f(x)
            return x

        unrelated = {"oid": self.w.sha["head"], "rawBase64": mid[0]["rawBase64"]}
        cases = {
            "skipped": {**good, "commits": [mid[0], mid[-1]]},
            "reordered": {**good, "commits": [mid[0], mid[2], mid[1]]},
            "reversed": {**good, "commits": mid[::-1]},
            "truncated tail": {**good, "commits": mid[:-1]},
            "duplicate": {**good, "commits": [mid[0], mid[1], mid[1], mid[2]]},
            "cyclic": {**good, "commits": [mid[0], mid[1], mid[0]]},
            "tampered": mut(lambda x: x["commits"][1].update(rawBase64=base64.b64encode(
                base64.b64decode(x["commits"][1]["rawBase64"]) + b"x").decode())),
            "wrong oid": mut(lambda x: x["commits"][1].update(oid="0" * 40)),
            "bad base64": mut(lambda x: x["commits"][1].update(rawBase64="@@@@")),
            "newline base64": mut(lambda x: x["commits"][1].update(rawBase64=x["commits"][1]["rawBase64"] + "\n")),
            "type": mut(lambda x: x["commits"][1].update(rawBase64=5)),
            "extra key": mut(lambda x: x["commits"][1].update(message="m")),
            "schema": mut(lambda x: x.update(schema="benchmark-ancestry@9")),
            "single": {**good, "commits": mid[:1]},
            "self pair": {**good, "commits": [unrelated, unrelated]},
            "oversize raw": mut(lambda x: x["commits"][1].update(rawBase64=base64.b64encode(b"a" * 70000).decode())),
            "not a dict": [],
        }
        for name, p in cases.items():
            with self.subTest(name):
                self.refuse_with(self.w.new_decision(p))

    def test_flag_and_mode_ambiguity_refused(self):
        g = self.good()
        for name, d in {
            "false flag": {**self.w.new_decision(g), "mergeBaseAncestryVerified": False},
            "string flag": {**self.w.new_decision(g), "mergeBaseAncestryVerified": "true"},
            "mixed legacy true": self.w.new_decision(g, drop=(), originalHeadSoleParentIsBase=True),
            "mixed legacy false": self.w.new_decision(g, drop=(), originalHeadSoleParentIsBase=False),
            "flag only": {k: v for k, v in self.w.new_decision(g).items() if k != "ancestryProof"},
            "proof only": {k: v for k, v in self.w.new_decision(g).items() if k != "mergeBaseAncestryVerified"},
            "common check dropped": {k: v for k, v in self.w.new_decision(g).items() if k != "rawCommitObjectsHashVerified"},
            "paid calls": {**self.w.new_decision(g), "newPaidCalls": 1},
            "repo": {**self.w.new_decision(g), "resolvedRepo": "o/other"},
        }.items():
            with self.subTest(name):
                self.refuse_with(d)

    def test_oversize_decision_document_refused(self):
        g = self.good()
        g["commits"] = g["commits"] * 400                                      # >1 MiB document
        self.refuse_with(self.w.new_decision(g))

    def test_chain_endpoints_must_match_verified_import_records(self):
        chain = verify_chain(self.good(), self.w.sha["head"], self.w.sha["base"])
        self.assertEqual(chain[0][2], self.w.imports["head"].record["parents"])
        self.assertEqual(chain[-1][2], self.w.imports["base"].record["parents"])
        self.assertEqual(chain[-1][1], self.w.imports["base"].record["treeOid"])

    def test_chain_must_start_at_the_proof_head_and_end_at_the_proof_base(self):
        p = self.good()
        with self.assertRaisesRegex(AncestryError, "start at"):
            verify_chain({**p, "commits": p["commits"][1:]}, self.w.sha["head"], self.w.sha["base"])
        with self.assertRaisesRegex(AncestryError, "end at"):
            verify_chain({**p, "commits": p["commits"][:-1]}, self.w.sha["head"], self.w.sha["base"])
        self.refuse_with(self.w.new_decision({**p, "commits": p["commits"][1:]}), "start at")

    def test_endpoint_binding_to_real_import_records(self):
        """Unreachable end-to-end (the importer already pins commit/tree/parents), so checked on the real records."""
        from reviewer.pilot.ancestry import check_endpoints
        chain = verify_chain(self.good(), self.w.sha["head"], self.w.sha["base"])
        h, b = self.w.imports["head"].record, self.w.imports["base"].record
        check_endpoints(chain, h, b)
        for name, hh, bb in (("head tree", {**h, "treeOid": b["treeOid"]}, b), ("head parents", {**h, "parents": []}, b),
                             ("base parents", h, {**b, "parents": ["1" * 40]}), ("base commit", h, {**b, "commitSha": h["commitSha"]}),
                             ("swapped", b, h)):
            with self.subTest(name), self.assertRaises(AncestryError):
                check_endpoints(chain, hh, bb)

    def test_chain_for_a_foreign_unrelated_base_refused_at_verify(self):
        r = self.w.src
        git(r, "checkout", "-q", "--orphan", "other")
        (r / "z").write_text("z")
        git(r, "add", "-A", "-f")
        git(r, "commit", "-q", "-m", "orphan", "--no-verify")
        orphan = git(r, "rev-parse", "HEAD")
        p = chain_doc(r, [self.w.path[0], orphan])
        with self.assertRaises(AncestryError):
            verify_chain(p, self.w.path[0], orphan)


class LinearWorld(Positive, WorldCase):
    shape = "linear"

    def test_legacy_decision_still_refused_only_because_head_has_a_parent_chain(self):
        self.assertEqual(self.w.imports["head"].record["parents"], [self.w.path[1]])


class MergeSecondParentWorld(Positive, WorldCase):
    shape = "merge"

    def test_base_is_reached_through_second_parent_only(self):
        head_parents = self.w.imports["head"].record["parents"]
        self.assertEqual(len(head_parents), 2)
        self.assertEqual(head_parents[1], self.w.path[1])
        self.assertNotIn(self.w.sha["base"], head_parents)
        self.assertEqual(self.w.path[2], self.w.sha["base"])

    def test_first_parent_path_does_not_reach_base(self):
        main_parent = [p for p in self.w.imports["head"].record["parents"] if p != self.w.path[1]][0]
        p = chain_doc(self.w.src, [self.w.path[0], main_parent, self.w.path[2]])
        self.refuse_with(self.w.new_decision(p))


class ParserNote(unittest.TestCase):
    def test_shared_parser_accepts_any_parent_header_line(self):
        """Documents (does not assert a defect): repoimport's helper is the single parser for both imports and chain."""
        from reviewer.repoimport.gitobjects import commit_tree_and_parents
        t, ps = commit_tree_and_parents(b"tree " + b"a" * 40 + b"\nauthor x\nparent " + b"b" * 40 + b"\n\nmsg parent " + b"c" * 40)
        self.assertEqual(ps, ["b" * 40])


if __name__ == "__main__":
    unittest.main()
