"""V27-D (res2 CARD-v27-build part D; root v27-decisions 2026-11-13 pick A): base-side anchors for DELETED files behind
`base_side_anchors` (OFF by default; impact@v26 only). Offline on the v26 rig (test_consensus_v26.V26Rig on the v12 mini case, whose
change deletes src/old.py): no network, no credential, no model call.
  1. seeded.drafts: flag off (no `base`) is byte-identical to the pre-change rule (a deleted file's item -> 'not-a-changed-file');
     with `base` a deleted file's item cites the base line (commit = the base id); past the base file's end -> 'no-such-line';
     modified paths and paths not listed as deleted are unchanged;
  2. end to end: flag off drops the deleted-file candidate as 'not-a-changed-file'; flag on publishes it anchored on the BASE
     snapshot (side 'base'), the head-side comment unchanged, strict replay identical; the run identity binds the rule only when on;
     a line past the base file and an exact rename are not anchored;
  3. contracts / judging: anchor side is Enum('base') only; revalidate_comment refuses side 'base' without the flag's base snapshot,
     with a head snapshotId, and with lines past the base file; head-side comments are checked as before;
  4. scoring: matching.is_foreign accepts the base snapshot for a side-'base' comment only when a base snapshot id is given (gate-v27d
     I-D1: also when it is the only id given);
  4b. gate-v27d F-D1 / I-D2: an unchanged twin file is no rename target; _judge_v26 with the flag off never anchors on the base;
  5. benchmark options: base_side_anchors is a bool and impact_version 26's only; ReviewSpec / BenchmarkOptions default False."""
from __future__ import annotations

import dataclasses
import json
import types
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import validate
from reviewer.pilot import benchmark as B
from reviewer.pipeline import identity, judging, seeded, spec as SP
from reviewer.pipeline.engine import Engine
from reviewer.scoring.matching import match_comments

import tests.pilot.test_benchmark_host as TBH
from tests.pipeline import test_consensus_v26 as C
from tests.pipeline import test_dual_v21 as T
from tests.pipeline.test_coverage_v12 import CORE_BASE, CORE_HEAD, md_of, payload

OLD = "OLD was removed but src/use.py still reads src.old.OLD at import"     # the deleted file's candidate (src/old.py:1)
HID, BID = "snap:sha256:" + "1" * 64, "snap:sha256:" + "2" * 64                                # snapshot-id shaped (HypothesisDraft evidence)


def lines_of(files):
    return lambda p: files[p].split("\n")[:-1] if p in files else None


class Drafts(unittest.TestCase):
    BASE = {"src/old.py": "OLD = 1\n", "src/lib.py": "a\nb\n", "src/moved.py": "M = 1\n"}
    HEAD = {"src/lib.py": "a\nB\n", "src/new.py": "M = 1\n"}
    ITEMS = [C.it(0, "src/old.py", 1, "x"), C.it(1, "src/old.py", 2, "y"), C.it(2, "src/lib.py", 2, "z"),
             C.it(3, "src/gone.py", 1, "w"), C.it(4, "src/moved.py", 1, "v"), C.it(5, "../x.py", 1, "u")]
    CHANGED = {"src/lib.py", "src/new.py"}

    def test_off_is_the_pre_change_rule(self):
        doc = {"items": self.ITEMS}
        a = seeded.drafts(doc, lines_of(self.HEAD), HID, self.CHANGED)
        b = seeded.drafts(doc, lines_of(self.HEAD), HID, self.CHANGED, base=None)
        self.assertEqual(a, b)
        out, dropped, cut = a
        self.assertEqual([n for n, _ in out], [2])
        self.assertEqual(dropped, [{"index": 0, "reason": "not-a-changed-file"}, {"index": 1, "reason": "not-a-changed-file"},
                                   {"index": 3, "reason": "not-a-changed-file"}, {"index": 4, "reason": "not-a-changed-file"},
                                   {"index": 5, "reason": "bad-path"}])
        self.assertEqual(out[0][1]["evidence"][0]["commit"], HID)

    def test_on_anchors_a_deleted_file_on_the_base(self):
        doc = {"items": self.ITEMS}
        off, _, _ = seeded.drafts(doc, lines_of(self.HEAD), HID, self.CHANGED)
        out, dropped, cut = seeded.drafts(doc, lines_of(self.HEAD), HID, self.CHANGED,
                                          base=(lines_of(self.BASE), BID, {"src/old.py"}))
        self.assertEqual([n for n, _ in out], [0, 2])
        d0 = dict(out)[0]
        self.assertEqual((d0["location"], d0["evidence"]), ({"path": "src/old.py", "line": 1},        # Location keeps its shape
                                                            [{"kind": "code", "path": "src/old.py", "lines": [1, 1],
                                                              "commit": BID, "excerpt": "OLD = 1"}]))
        self.assertEqual(dict(out)[2], dict(off)[2])                                   # a modified path: unchanged, head side
        self.assertEqual(dropped, [{"index": 1, "reason": "no-such-line"},              # past the base file's end
                                   {"index": 3, "reason": "not-a-changed-file"},        # not a deleted path either
                                   {"index": 4, "reason": "not-a-changed-file"},        # not listed as deleted (e.g. a rename)
                                   {"index": 5, "reason": "bad-path"}])
        self.assertEqual(validate("HypothesisDraft", d0), [])


class Deleted(unittest.TestCase):
    def test_deleted_base_paths(self):
        def man(d):
            return types.SimpleNamespace(manifest={"entries": [{"path": p, "sha256": s} for p, s in d.items()]})
        spec = types.SimpleNamespace(base=man({"a.py": "1", "b.py": "2", "c.py": "3", "r.py": "4", "g.py": "5"}),
                                     head=man({"a.py": "1x", "n.py": "4"}))
        files = [{"path": "a.py", "status": "modified"}, {"path": "b.py", "status": "deleted"}, {"path": "r.py", "status": "deleted"},
                 {"path": "g.py", "status": "modified"},       # a recorded one-sided gap row: absent from the head, NOT a deletion
                 {"path": "n.py", "status": "added"}, {"path": "x.py", "status": "deleted"}]   # x.py: not in the base manifest
        eng = types.SimpleNamespace(spec=spec, artifacts={"PREPARE": {"payload": {"files": files}}})
        self.assertEqual(Engine.deleted_base_paths(eng), {"b.py"})     # r.py: head n.py holds its blob (an exact rename); c.py: unlisted

    def test_an_unchanged_twin_is_not_a_rename_target(self):
        """gate-v27d F-D1: only an ADDED head path (absent from the base) can be a rename target; an unchanged file with the same
        bytes (two identical __init__.py) leaves the delete a delete. ccb-gate's probe/fix_d1_check.py cases."""
        def eng(base, head, files):
            man = lambda d: types.SimpleNamespace(manifest={"entries": [{"path": p, "sha256": s} for p, s in d.items()]})
            return types.SimpleNamespace(spec=types.SimpleNamespace(base=man(base), head=man(head)),
                                         artifacts={"PREPARE": {"payload": {"files": files}}})
        deleted, added = {"path": "a.py", "status": "deleted"}, {"path": "c.py", "status": "added"}
        for name, e, want in (("plain delete", eng({"a.py": "1", "k.py": "9"}, {"k.py": "9"}, [deleted]), {"a.py"}),
                              ("delete + unchanged twin", eng({"a.py": "1", "t.py": "1"}, {"t.py": "1"}, [deleted]), {"a.py"}),
                              ("exact rename", eng({"a.py": "1"}, {"c.py": "1"}, [deleted, added]), set()),
                              ("rename + unchanged twin", eng({"a.py": "1", "t.py": "1"}, {"c.py": "1", "t.py": "1"}, [deleted, added]), set())):
            with self.subTest(name):
                self.assertEqual(Engine.deleted_base_paths(e), want)


class JudgeV26FlagOff(unittest.TestCase):
    """gate-v27d I-D2: _judge_v26 itself, flag off, a finding on a DELETED path: it anchors on the head (where the file is absent) and
    is dropped 'suppressed'; deleted_base_paths is never consulted (pins the gate's defence-in-depth line)."""
    def test_deleted_path_finding_is_suppressed_on_the_head(self):
        seed = {"candidates": {"items": [{"id": "ccbo-mini-6", "body": OLD}]}}
        ref = "sha256:" + seeded.digest(seed)
        f = {"id": "fnd_1", "location": {"path": "src/old.py", "line": 1}, "seedRef": {"seed": ref, "index": 0, "id": "ccbo-mini-6"}}
        deleted = mock.Mock(return_value={"src/old.py"})
        eng = types.SimpleNamespace(
            recorder=types.SimpleNamespace(events=[]), tool_calls=lambda: [], deleted_base_paths=deleted, set_fatal=mock.Mock(),
            spec=types.SimpleNamespace(seed=seed, base_side_anchors=False, head=types.SimpleNamespace(root="HEAD", manifest={}),
                                       base=types.SimpleNamespace(root="BASE", manifest={})))
        anchor = lambda root, manifest, path, a, b: "OLD = 1\n" if root == "BASE" else None   # src/old.py exists on the base only
        with mock.patch("reviewer.pipeline.engine.check_finding_provenance", return_value=[]), \
                mock.patch("reviewer.pipeline.engine.snaps.anchor_text", side_effect=anchor):
            comments, drops, extra = Engine._judge_v26(eng, [f])
        self.assertEqual((comments, extra), ([], []))
        self.assertEqual(drops, [{"subjectIds": ["fnd_1"], "stage": "JUDGE", "reason": "suppressed",
                                  "detail": "anchor lines do not exist in the pinned head file"}])
        deleted.assert_not_called()
        eng.set_fatal.assert_not_called()


class Rig(C.V26Rig):
    base_side = False

    def spec(self, mini, backend, **kw):
        return dataclasses.replace(super().spec(mini, backend, **kw), base_side_anchors=self.base_side)

    def seed_with_old(self, line=1):
        items = C.S.ITEMS + [C.it(6, "src/old.py", line, OLD, "ccbo-mini")]
        ws = C.W + [C.it(4, "src/old.py", line, OLD, "ccbs-mini")]
        return C.seed_doc(items=items, witnesses=[ws])

    def run_case(self, name, line=1, head=None):
        m = self.mini(f"mini-{name}", base=CORE_BASE, head=head or CORE_HEAD)
        self.seed = self.seed_with_old(line)
        res, _ = self.record_v26(m, out_root=self.fresh(f"o-{name}"))
        self.assertEqual(res.status, "completed", res.receipt)
        return m, res


class EndToEnd(Rig):
    def test_off_drops_the_deleted_file_candidate(self):
        self.base_side = False
        m, res = self.run_case("off")
        rec = payload(res, "INVESTIGATE")["consensus"]
        self.assertIn({"index": 6, "id": "ccbo-mini-6", "reason": "not-a-changed-file"}, rec["dropped"])
        cs = T.comments_of(res)
        self.assertEqual([(c["anchor"]["path"], c["anchor"]["startLine"]) for c in cs], [("src/lib.py", 1)])
        self.assertTrue(all("side" not in c["anchor"] for c in cs))
        backend, _ = self.record_backend(C.script())
        self.assertEqual(res.run["configSnapshotId"], identity.config_snapshot_id(
            self.spec(m, backend, profile=C.V26_PROFILE, plan=C.V26_PLAN, retrieval=C.V26_POLICY)))

    def test_on_anchors_the_deleted_file_on_the_base_snapshot(self):
        self.base_side = False
        _, off = self.run_case("off2")
        self.base_side = True
        m, res = self.run_case("on")
        rec = payload(res, "INVESTIGATE")["consensus"]
        self.assertNotIn(6, [d["index"] for d in rec["dropped"]])
        cs = T.comments_of(res)
        self.assertEqual([(c["anchor"]["path"], c["anchor"].get("side")) for c in cs], [("src/lib.py", None), ("src/old.py", "base")])
        old = cs[1]
        base_id = payload(res, "PREPARE")["baseSnapshotId"]
        self.assertEqual((old["anchor"]["snapshotId"], old["anchor"]["startLine"], old["anchor"]["endLine"], old["body"]), (base_id, 1, 1, OLD))
        self.assertEqual(validate("Comment", old), [])
        self.assertEqual({k: v for k, v in cs[0].items() if k != "runId"}, {k: v for k, v in T.comments_of(off)[0].items() if k != "runId"})
        cdoc = json.loads((Path(res.run_dir) / "comments.json").read_text())
        self.assertEqual(cdoc["seedIds"][old["id"]], ["ccbo-mini-6"])
        self.assertNotEqual(res.run["configSnapshotId"], off.run["configSnapshotId"])   # the rule binds the identity only when on
        rep = self.replay_v26(m, res)
        self.assertEqual(rep.status, "completed", rep.incomplete)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])
        self.assertIn("- Published: 2 comment(s)", md_of(res))

    def test_on_a_line_past_the_base_file_and_an_exact_rename(self):
        self.base_side = True
        _, res = self.run_case("past", line=5)
        self.assertIn({"index": 6, "id": "ccbo-mini-6", "reason": "no-such-line"}, payload(res, "INVESTIGATE")["consensus"]["dropped"])
        head = dict(CORE_HEAD, **{"src/renamed.py": CORE_BASE["src/old.py"]})           # the same blob on the head side: a rename
        _, res = self.run_case("rename", head=head)
        self.assertIn({"index": 6, "id": "ccbo-mini-6", "reason": "not-a-changed-file"},
                      payload(res, "INVESTIGATE")["consensus"]["dropped"])


class Identity(Rig):
    """The rule enters BOTH identities only when on: the pipeline's config_snapshot_id document and the benchmark config identity."""
    def test_pipeline_identity_doc(self):
        m = self.case12()
        backend, _ = self.record_backend(C.script())
        self.seed = C.seed_doc()
        docs, real = [], identity.config_digest
        with mock.patch.object(identity, "config_digest", side_effect=lambda d: (docs.append(d), real(d))[1]):
            for on in (False, True):
                self.base_side = on
                identity.config_snapshot_id(self.spec(m, backend, profile=C.V26_PROFILE, plan=C.V26_PLAN, retrieval=C.V26_POLICY))
        off, on = docs
        self.assertNotIn("baseSideAnchors", off["impact"])
        self.assertEqual(on["impact"]["baseSideAnchors"], seeded.BASE_SIDE_RULE)
        self.assertEqual({k: v for k, v in on["impact"].items() if k != "baseSideAnchors"}, off["impact"])
        self.assertEqual({k: v for k, v in on.items() if k != "impact"}, {k: v for k, v in off.items() if k != "impact"})

    def test_benchmark_config_identity(self):
        rec = types.SimpleNamespace(record={"r": 1}, snapshot_id="snap:sha256:" + "3" * 64)
        ing = B.BenchIngested("https://github.com/o/r/pull/1", "case_" + "4" * 16, {}, "o/r",
                              {"asOfBase": "a", "asOfHead": "b", "mergeBase": "c"}, {}, rec, rec, {"base": {}, "head": {}}, ("a.py",),
                              dict.fromkeys(("proofSha256", "admissionDigest", "decisionSha256", "baselineDigest", "authorizationSha256"), "x"),
                              Path("/nonexistent"), None)
        cfg = types.SimpleNamespace(models=types.SimpleNamespace(digest="m"))
        off = B.config_identity(ing, {"p": 1}, {"q": 1}, None, False, cfg)
        on = B.config_identity(dataclasses.replace(ing, base_side_anchors=True), {"p": 1}, {"q": 1}, None, False, cfg)
        self.assertNotIn("baseSideAnchors", off)
        self.assertEqual(on, dict(off, baseSideAnchors=seeded.BASE_SIDE_RULE))


class Judging(unittest.TestCase):
    HEAD, BASE = HID, BID

    def comment(self, **kw):
        f = {"id": "hyp_" + "a" * 16, "claim": OLD, "category": "bug", "suspectedSeverity": "P1",
             "location": {"path": "src/old.py", "line": 1},
             "evidence": [{"kind": "code", "path": "src/old.py", "lines": [1, 1], "commit": self.BASE, "excerpt": "OLD = 1",
                           "source": "seed:reuse", "resolved": True}],
             "impact": seeded.IMPACT, "severityBasis": {"impact": seeded.IMPACT, "reachable": False}, "verification": {"evidence": []}}
        return judging.build_comment(f, run_id="run_" + "c" * 16, head_snapshot_id=self.HEAD, anchor="OLD = 1",
                                     tool_calls={}, title="t", body="b", suggestion=None, **kw)

    def test_build_and_revalidate(self):
        head, base = self.HEAD, self.BASE
        h = self.comment()
        self.assertEqual((h["anchor"]["snapshotId"], "side" in h["anchor"]), (head, False))       # unchanged without the base id
        c = self.comment(base_snapshot_id=base)
        self.assertEqual((c["anchor"]["snapshotId"], c["anchor"]["side"]), (base, "base"))
        self.assertEqual(validate("Comment", c), [])
        self.assertNotEqual(validate("Comment", dict(c, anchor=dict(c["anchor"], side="head"))), [])
        ok, no = (lambda *a: True), (lambda *a: False)

        def rv(x, **kw):
            return judging.revalidate_comment(x, head_snapshot_id=head, resolver=lambda e: True, anchor_ok=ok, **kw)
        need = "a base-side comment needs base_side_anchors and the base snapshot"
        self.assertEqual(rv(h), [])
        self.assertEqual(rv(c, base_snapshot_id=base, base_anchor_ok=ok), [])
        self.assertIn(need, rv(c))                                                                  # flag off
        self.assertIn(need, rv(dict(c, anchor=dict(c["anchor"], snapshotId=head)), base_snapshot_id=base, base_anchor_ok=ok))
        self.assertIn("anchor lines do not exist in the pinned base file", rv(c, base_snapshot_id=base, base_anchor_ok=no))
        self.assertIn("comment is not anchored to the head snapshot",                              # head side as before
                      rv(dict(h, anchor=dict(h["anchor"], snapshotId=base)), base_snapshot_id=base, base_anchor_ok=ok))


class Matching(unittest.TestCase):
    def test_is_foreign_base_side(self):
        head, base, run = HID, BID, "run_" + "c" * 16
        c = {"id": "cmt_1", "runId": run, "state": "draft", "anchor": {"path": "src/old.py", "startLine": 1, "endLine": 1,
                                                                       "snapshotId": base, "side": "base"}}
        bugs = [{"id": "bug_1", "path": "src/old.py", "lines": [1, 1]}]
        self.assertEqual(match_comments([c], bugs, 0, head_snapshot_id=head, run_id=run).foreign, ("cmt_1",))   # no base id
        r = match_comments([c], bugs, 0, head_snapshot_id=head, run_id=run, base_snapshot_id=base)
        self.assertEqual((r.foreign, r.true_positives), ((), 1))
        wrong = dict(c, anchor=dict(c["anchor"], snapshotId=head))                      # side 'base' on the head snapshot
        self.assertEqual(match_comments([wrong], bugs, 0, head_snapshot_id=head, run_id=run, base_snapshot_id=base).foreign, ("cmt_1",))
        plain = dict(c, anchor={k: v for k, v in c["anchor"].items() if k != "side"})  # no side: the head rule, unchanged
        self.assertEqual(match_comments([plain], bugs, 0, head_snapshot_id=head, run_id=run, base_snapshot_id=base).foreign, ("cmt_1",))
        # gate-v27d I-D1: a caller passing ONLY the base snapshot id still checks side-'base' comments against it
        self.assertEqual(match_comments([c], bugs, 0, run_id=run, base_snapshot_id=base).foreign, ())
        self.assertEqual(match_comments([wrong], bugs, 0, run_id=run, base_snapshot_id=base).foreign, ("cmt_1",))
        self.assertEqual(match_comments([plain], bugs, 0, run_id=run, base_snapshot_id=base).foreign, ())      # head side: no head id given


class Options(TBH.Base):
    def test_base_side_anchors_is_v26_only_and_a_bool(self):
        msg = "base_side_anchors is only for impact_version 26 (a bool, False by default)"
        for over in ({"base_side_anchors": True}, {"base_side_anchors": True, "impact_version": 21},
                     {"base_side_anchors": 1, "impact_version": 26, "seed_candidates": "x.json"},
                     {"base_side_anchors": "yes", "impact_version": 26, "seed_candidates": "x.json"}):
            with self.subTest(**over):
                self.assertEqual(self.refused(**over), msg)
        self.assertIs(B.BenchmarkOptions.__dataclass_fields__["base_side_anchors"].default, False)
        self.assertIs(SP.ReviewSpec.__dataclass_fields__["base_side_anchors"].default, False)
        self.assertEqual(seeded.BASE_SIDE_RULE, "base-side-anchors@1")


if __name__ == "__main__":
    unittest.main()
