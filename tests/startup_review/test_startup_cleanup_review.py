"""S1-16-review: independent acceptance of pre-contact startup cleanup. Evaluator-owned; product/author tests untouched.

Every test drives run_review end to end (or RunDir.remove_empty directly) and compares whole-tree snapshots, so a
cleanup that removes someone else's bytes fails by content, not by a hand-picked path."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from reviewer.pipeline import Hooks, PipelineError, ReplayBackend, RecordBackend, identity, run_review
from reviewer.pipeline.store import RunDir

from tests.pipeline.helpers import Crash, Rig, inv, script
from tests.pipeline.test_replay_failures import Base


def tree(root: Path) -> dict:
    """path -> ('d'|'l:<target>'|'f:<sha256>') for everything under root, symlinks not followed."""
    out = {}
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        if p.is_symlink():
            out[rel] = "l:" + os.readlink(p)
        elif p.is_dir():
            out[rel] = "d"
        else:
            out[rel] = "f:" + hashlib.sha256(p.read_bytes()).hexdigest()
    return out


class Planting(RecordBackend):
    """Fails make_gateway after letting `plant(run_dir)` put things in the (empty, freshly created) run dir."""
    plant = None
    seen = None

    def make_gateway(self, *, recorder, **kw):
        run_dir = Path(os.readlink(f"/proc/self/fd/{recorder._f.fileno()}")).parent
        Planting.seen = sorted(p.name for p in run_dir.iterdir())     # proves the dir exists with a trace pre-contact
        if Planting.plant:
            Planting.plant(run_dir)
        raise PipelineError("config", "refused before contact")


class Review(Rig):
    def backend(self, cls=Planting, plant=None):
        spy_backend, spy = self.record_backend(script(inv()))
        Planting.plant, Planting.seen = plant, None
        self.addCleanup(setattr, Planting, "plant", None)
        return cls(self.handle, self.book, spy_backend.providers, spy_backend.clock), spy

    def run_id(self, m, backend):
        probe = self.spec(m, backend)
        return identity.build_run(probe, backend, identity.config_snapshot_id(probe))["id"]


class PreContact(Review):
    def test_new_dir_with_a_trace_is_removed_typed_error_kept_no_contact_and_same_root_recovers(self):
        m = self.mini()
        bad, spy = self.backend()
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, bad))
        self.assertEqual(Planting.seen, ["trace.jsonl"])               # a real new dir holding run.start existed
        self.assertEqual((cm.exception.code, str(cm.exception)), ("config", "config: refused before contact"))
        self.assertEqual((tree(self.out), spy.calls), ({}, 0))
        good, gspy = self.record_backend(script(inv()))
        res = run_review(self.spec(m, good))
        self.assertEqual((res.status, [p.name for p in self.out.iterdir()]), ("completed", [res.run_id]))
        again = run_review(self.spec(m, good))                         # and a second failure path is repeatable
        self.assertTrue(again.idempotent)

    def test_repeated_failures_in_one_root_never_accumulate_directories(self):
        m = self.mini()
        for _ in range(3):
            bad, spy = self.backend()
            with self.assertRaises(PipelineError):
                run_review(self.spec(m, bad))
        self.assertEqual(tree(self.out), {})

    def test_no_spend_is_recorded_by_the_refused_startup(self):
        m = self.mini()
        bad, spy = self.backend()
        before = tree(self.tmp / "operator")
        with self.assertRaises(PipelineError):
            run_review(self.spec(m, bad))
        self.assertEqual((tree(self.tmp / "operator"), spy.calls), (before, 0))

    def test_sibling_run_dirs_and_files_in_the_out_root_are_untouched(self):
        m = self.mini()
        (self.out / "run_other").mkdir()
        (self.out / "run_other" / "trace.jsonl").write_bytes(b"theirs\n")
        (self.out / "note.txt").write_text("keep")
        before = tree(self.out)
        bad, _ = self.backend()
        with self.assertRaises(PipelineError):
            run_review(self.spec(m, bad))
        self.assertEqual(tree(self.out), before)


class Survivors(Review):
    def test_a_foreign_empty_dir_with_our_run_id_survives(self):
        m = self.mini()
        bad, spy = self.backend()
        (self.out / self.run_id(m, bad)).mkdir(mode=0o700)
        before = tree(self.out)
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, bad))
        after = tree(self.out)
        self.assertEqual((cm.exception.code, spy.calls, (self.out / self.run_id(m, bad)).is_dir()), ("config", 0, True))
        self.assertTrue(set(before) <= set(after))                      # nothing that existed was removed
        # observation, not a requirement: an existing empty dir is adopted as a restartable run, so its own
        # run.start trace is left behind (nothing deleted; same behaviour as before S1-16)
        print(f"\n[observe] foreign empty dir after refused startup: {sorted(after)}")

    def test_a_foreign_dir_with_foreign_files_and_subdir_survives_byte_for_byte(self):
        m = self.mini()
        bad, _ = self.backend()
        d = self.out / self.run_id(m, bad)
        d.mkdir(mode=0o700)
        (d / "trace.jsonl").write_bytes(b"not ours\n")
        (d / "artifacts").mkdir()
        (d / "artifacts" / "x.json").write_bytes(b"{}")
        before = tree(self.out)
        with self.assertRaises(PipelineError):
            run_review(self.spec(m, bad))
        self.assertEqual(tree(self.out), before)

    def test_a_completed_run_survives_a_refusing_backend_and_is_reused(self):
        m = self.mini()
        good, _ = self.record_backend(script(inv()))
        res = run_review(self.spec(m, good))
        before = tree(self.out)
        bad, spy = self.backend()
        out = run_review(self.spec(m, bad))
        self.assertEqual((out.idempotent, tree(self.out), spy.calls), (True, before, 0))

    def test_a_model_call_in_the_trace_keeps_the_whole_dir(self):
        m = self.mini()

        class Contact(Planting):
            def make_gateway(self, *, recorder, **kw):
                recorder.events.append({"type": "model.call"})
                recorder._f.write('{"type": "model.call"}\n')
                recorder._f.flush()
                return super().make_gateway(recorder=recorder, **kw)
        bad, _ = self.backend(Contact, plant=lambda d: (d / "extra.txt").write_text("evidence"))
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, bad))
        self.assertEqual(cm.exception.code, "config")
        (d,) = list(self.out.iterdir())
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["extra.txt", "trace.jsonl"])
        self.assertIn(b"model.call", (d / "trace.jsonl").read_bytes())


class Resumed(Base):
    def test_a_resumed_run_survives_a_refusing_backend_with_every_byte_and_the_error_is_typed(self):
        with self.assertRaises(Crash):
            self.replay(self.m, self.rec, hooks=Hooks(after_checkpoint=lambda st, d: (_ for _ in ()).throw(Crash(st))
                                                      if st == "TRIAGE" else None))
        d = self.out / self.rec.run_id
        before = tree(self.out)
        self.assertTrue((d / "trace.jsonl").is_file())

        class Refusing(ReplayBackend):
            def make_gateway(self, **kw):
                raise PipelineError("config", "resume refused")
        self.replay_backend = lambda res, **kw: Refusing(res.trace_path, res.receipt["traceDigest"], "test-pin")
        with self.assertRaises(PipelineError) as cm:
            self.replay(self.m, self.rec)
        self.assertEqual(cm.exception.code, "config")
        after = tree(self.out)
        for k, v in before.items():                                     # nothing deleted; trace may be moved aside only
            if k != "run_" and k in after:
                self.assertEqual(after[k], v, k)
        self.assertTrue(d.is_dir())
        self.assertTrue(any(k.endswith("trace.jsonl") or "interrupted" in k for k in after if k.startswith(d.name)))
        self.assertEqual(sorted(k for k in before if k.startswith(d.name + "/artifacts/")),
                         sorted(k for k in after if k.startswith(d.name + "/artifacts/")))


class Boundaries(Review):
    """Planted entries inside a NEW dir, driven through run_review (the dir is ours, the contents are hostile)."""

    def test_a_symlink_to_a_caller_file_is_unlinked_and_the_target_is_not_touched(self):
        keep = self.tmp / "caller.txt"
        keep.write_text("mine")
        bad, _ = self.backend(plant=lambda d: os.symlink(keep, d / "link"))
        with self.assertRaises(PipelineError):
            run_review(self.spec(self.mini(), bad))
        self.assertEqual((keep.read_text(), tree(self.out)), ("mine", {}))

    def test_a_dangling_symlink_and_a_symlink_to_a_directory_do_not_follow_or_recurse(self):
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "f").write_text("x")
        def plant(d):
            os.symlink(victim, d / "dirlink")
            os.symlink(self.tmp / "nowhere", d / "dangling")
        bad, _ = self.backend(plant=plant)
        with self.assertRaises(PipelineError):
            run_review(self.spec(self.mini(), bad))
        self.assertEqual(tree(victim), {"f": tree(victim)["f"]})
        self.assertEqual((victim / "f").read_text(), "x")
        self.assertEqual(tree(self.out), {})

    def test_a_subdirectory_is_never_recursed_and_its_contents_survive(self):
        def plant(d):
            (d / "sub").mkdir()
            (d / "sub" / "deep.txt").write_bytes(b"deep")
            (d / "sub" / "inner").mkdir()
        bad, _ = self.backend(plant=plant)
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(self.mini(), bad))
        self.assertEqual(cm.exception.code, "config")
        (d,) = list(self.out.iterdir())
        self.assertEqual(sorted(str(p.relative_to(d)) for p in d.rglob("*")), ["sub", "sub/deep.txt", "sub/inner"])
        self.assertEqual((d / "sub" / "deep.txt").read_bytes(), b"deep")

    def test_an_undeletable_dir_keeps_the_typed_error_and_loses_nothing_else(self):
        def plant(d):
            (d / "locked.txt").write_text("kept")
            d.chmod(0o500)                                              # unlink inside is refused
        bad, _ = self.backend(plant=plant)
        m = self.mini()
        try:
            with self.assertRaises(PipelineError) as cm:
                run_review(self.spec(m, bad))
        finally:
            for p in self.out.iterdir():
                p.chmod(0o700)
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        self.assertEqual(cm.exception.code, "config")
        (d,) = list(self.out.iterdir())
        self.assertEqual((d / "locked.txt").read_text(), "kept")        # failure to clean never raises over the cause


class FreshFd(Rig):
    def test_listing_through_a_dir_fd_opened_before_the_file_exists_is_handled(self):
        rd = RunDir.open(self.out, "run_fd", create=True)
        self.addCleanup(rd.close)
        stale = os.open(rd.path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, stale)
        (rd.path / "trace.jsonl").write_bytes(b"{}\n")
        first = os.listdir(stale)
        fresh = os.open(rd.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fresh_list = os.listdir(fresh)
        finally:
            os.close(fresh)
        print(f"\n[fs-probe] {self.out} stale-first={first} fresh={fresh_list}")
        self.assertEqual(fresh_list, ["trace.jsonl"])                   # a fresh fd always sees the entry
        rd.remove_empty()
        self.assertEqual(list(self.out.iterdir()), [])

    def test_remove_empty_closes_its_fresh_fd(self):
        before = len(os.listdir("/proc/self/fd"))
        for i in range(25):
            rd = RunDir.open(self.out, f"run_{i}", create=True)
            (rd.path / "trace.jsonl").write_bytes(b"{}\n")
            rd.remove_empty()
            rd.close()
        self.assertEqual((len(os.listdir("/proc/self/fd")), list(self.out.iterdir())), (before, []))

    def test_a_write_protected_entry_does_not_make_remove_empty_raise(self):
        rd = RunDir.open(self.out, "run_p", create=True)
        self.addCleanup(rd.close)
        (rd.path / "trace.jsonl").write_bytes(b"{}\n")
        rd.path.chmod(0o500)
        try:
            rd.remove_empty()                                           # must swallow, not raise
        finally:
            rd.path.chmod(0o700)
        if os.geteuid() != 0:
            self.assertEqual((rd.path / "trace.jsonl").read_bytes(), b"{}\n")
