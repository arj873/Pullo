"""S1-16: a failed pre-contact startup removes only what this process just created, and nothing else."""

from __future__ import annotations

import os
from pathlib import Path

from reviewer.pipeline import PipelineError, RecordBackend, run_review
from reviewer.pipeline.store import RunDir

from .helpers import Rig, inv, script


class Refusing(RecordBackend):
    def make_gateway(self, **kw):
        raise PipelineError("config", "gateway unavailable")


class ContactThenRefusing(RecordBackend):
    """Stand-in for a backend that already put a model.call on the trace before failing."""
    def make_gateway(self, *, recorder, **kw):
        recorder.events.append({"type": "model.call"})            # schema-bypassing marker; no provider is touched
        recorder._f.write('{"type": "model.call"}\n')
        recorder._f.flush()
        raise PipelineError("config", "late failure")


class StartupCleanup(Rig):
    def refusing(self, cls=Refusing):
        spy_backend, spy = self.record_backend(script(inv()))
        return cls(self.handle, self.book, spy_backend.providers, spy_backend.clock), spy

    def test_a_failed_startup_removes_its_new_run_dir_and_a_corrected_backend_then_runs_in_the_same_root(self):
        m = self.mini()
        bad, spy = self.refusing()
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, bad))
        self.assertEqual((cm.exception.code, list(self.out.iterdir()), spy.calls), ("config", [], 0))
        good, _ = self.record_backend(script(inv()))
        res = run_review(self.spec(m, good))
        self.assertEqual(res.status, "completed")
        self.assertEqual([p.name for p in self.out.iterdir()], [res.run_id])

    def test_a_pre_existing_run_dir_and_its_contents_are_never_removed(self):
        m = self.mini()
        good, _ = self.record_backend(script(inv()))
        res = run_review(self.spec(m, good))
        before = sorted(str(p.relative_to(self.out)) for p in self.out.rglob("*"))
        rd = self.out / res.run_id
        bad, spy = self.refusing()
        out = run_review(self.spec(m, bad))                          # idempotent reuse: make_gateway never reached
        self.assertTrue(out.idempotent)
        self.assertEqual(sorted(str(p.relative_to(self.out)) for p in self.out.rglob("*")), before)
        self.assertTrue(rd.is_dir())

    def test_an_empty_pre_existing_run_dir_is_not_ours_and_survives_a_failed_startup(self):
        m = self.mini()
        bad, spy = self.refusing()
        probe = self.spec(m, bad)
        with self.assertRaises(PipelineError):
            run_review(probe)                                         # cleaned
        from reviewer.pipeline import identity
        run = identity.build_run(probe, bad, identity.config_snapshot_id(probe))
        (self.out / run["id"]).mkdir(mode=0o700)                      # someone else's directory
        with self.assertRaises(PipelineError):
            run_review(self.spec(m, bad))
        self.assertTrue((self.out / run["id"]).is_dir())
        self.assertEqual(spy.calls, 0)

    def test_a_trace_already_holding_a_model_call_is_kept_as_evidence(self):
        m = self.mini()
        bad, spy = self.refusing(ContactThenRefusing)
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, bad))
        self.assertEqual(cm.exception.code, "config")
        (run_dir,) = list(self.out.iterdir())
        self.assertIn(b"model.call", (run_dir / "trace.jsonl").read_bytes())


class RemoveEmptyBoundaries(Rig):
    def open_dir(self, name="run_x"):
        rd = RunDir.open(self.out, name, create=True)
        self.addCleanup(rd.close)
        return rd

    def test_a_file_created_after_the_dir_fd_was_opened_is_removed(self):
        rd = self.open_dir()
        (rd.path / "trace.jsonl").write_bytes(b"{}\n")
        rd.remove_empty()
        self.assertEqual(list(self.out.iterdir()), [])

    def test_a_subdirectory_is_never_deleted_recursively_and_keeps_the_run_dir(self):
        rd = self.open_dir()
        rd.write_artifact("01-INGEST.v1.json", b"{}")
        (rd.path / "trace.jsonl").write_bytes(b"{}\n")
        rd.remove_empty()
        self.assertEqual(sorted(p.name for p in rd.path.rglob("*")), ["01-INGEST.v1.json", "artifacts"])

    def test_a_symlink_entry_is_unlinked_without_touching_its_target(self):
        rd = self.open_dir()
        keep = self.tmp / "caller.txt"
        keep.write_text("mine")
        os.symlink(keep, rd.path / "trace.jsonl")
        rd.remove_empty()
        self.assertEqual((keep.read_text(), list(self.out.iterdir())), ("mine", []))

    def test_a_symlinked_directory_entry_is_left_alone(self):
        rd = self.open_dir()
        target = self.tmp / "callerdir"
        target.mkdir()
        (target / "f").write_text("x")
        os.symlink(target, rd.path / "artifacts")
        rd.remove_empty()
        self.assertEqual((target / "f").read_text(), "x")
