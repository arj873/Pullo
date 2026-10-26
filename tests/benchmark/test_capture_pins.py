"""Consumer for root's actual capture format (invented values; same key set as the import receipt `files`)."""

import copy
import json

from reviewer.benchmark.__main__ import main
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.pins import load_pins, pin_for, verify_file

from .helpers import REV, Fx

RAW = "https://raw.githubusercontent.com/withmartian/code-review-benchmark/{}/offline/results/{}"


class CapturePins(Fx):
    def capture(self, mutate=None, top=None) -> dict:
        files = []
        for name, p in (("benchmark_data.json", self.dp), ("pr_labels.json", self.lp)):
            nat = next(f for f in self.pins()["files"] if f["name"] == name)
            keys = sorted(json.loads(p.read_text()))
            files.append({"path": f"/elsewhere/{name}", "sourcePath": f"offline/results/{name}",
                          "url": RAW.format(REV, name), "revision": REV, "bytes": nat["bytes"],
                          "gitBlobSha": nat["gitBlobSha"], "sha256": nat["sha256"],
                          "capturedAt": "2026-10-25T23:13:20.999827+00:00", "topType": "dict",
                          "topKeys": keys, "topCount": len(keys)})
        doc = {"schema": "benchmark-source-pins@1", "revision": REV, "capturedBy": "root host", "files": files}
        doc.update(top or {})
        if mutate:
            mutate(doc)
        return doc

    def write(self, doc):
        self.pins_path.write_text(json.dumps(doc))
        return self.pins_path

    def refused(self, doc, text=""):
        with self.assertRaises(BenchmarkError) as cm:
            load_pins(self.write(doc))
        self.assertEqual(cm.exception.code, "pins")
        self.assertIn(text, cm.exception.message)

    def test_actual_format_loads_end_to_end_with_explicit_paths(self):
        self.write(self.capture())
        s = self.source()
        self.assertEqual(s.report()["cases"], 6)
        pins = load_pins(self.pins_path)
        self.assertEqual({f["name"] for f in pins["files"]}, {"benchmark_data.json", "pr_labels.json"})
        self.assertEqual(set(pin_for(pins, "pr_labels.json")), {"name", "sourcePath", "bytes", "gitBlobSha", "sha256"})
        self.assertEqual(s.file_digests["pr_labels.json"], pin_for(pins, "pr_labels.json")["sha256"])

    def test_descriptive_path_is_never_opened_or_authoritative(self):
        doc = self.capture(lambda d: d["files"][0].update(path=str(self.tmp / "decoy" / "benchmark_data.json")))
        (self.tmp / "decoy").mkdir()
        (self.tmp / "decoy" / "benchmark_data.json").write_text("{}")
        self.write(doc)
        self.assertEqual(self.source().report()["cases"], 6)           # explicit CLI path wins
        other = self.store / "renamed.json"
        other.write_bytes(self.dp.read_bytes())
        with self.assertRaises(BenchmarkError):                         # a different filename is not the pinned one
            verify_file(other, pin_for(load_pins(self.pins_path), "pr_labels.json"))

    def test_tamper_controls_on_actual_format(self):
        self.write(self.capture())
        flipped = bytearray(self.dp.read_bytes())
        flipped[10] ^= 1
        self.dp.write_bytes(bytes(flipped))
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertEqual(cm.exception.code, "tamper")
        for field, val, word in (("sha256", "sha256:" + "0" * 64, "sha256"), ("gitBlobSha", "b" * 40, "Git blob")):
            self.write_all()
            self.write(self.capture(lambda d: d["files"][1].update({field: val})))
            with self.assertRaises(BenchmarkError) as cm:
                self.source()
            self.assertIn(word, cm.exception.message)

    def test_rejects_unknown_missing_and_misplaced_authority_fields(self):
        self.refused(self.capture(lambda d: d["files"][0].update(extra="x")), "file pin keys")
        self.refused(self.capture(lambda d: d["files"][0].pop("capturedAt")), "file pin keys")
        self.refused(self.capture(lambda d: d["files"][0].update(name="benchmark_data.json")), "file pin keys")
        self.refused(self.capture(top={"approved": True}), "capture pins keys")
        self.refused(self.capture(lambda d: d.pop("capturedBy")), "capture pins keys")
        mixed = self.capture()
        mixed["files"][1] = self.pins()["files"][1]
        self.refused(mixed, "file pin keys")

    def test_rejects_duplicates_and_ambiguous_or_unknown_names(self):
        self.refused(self.capture(lambda d: d["files"].append(copy.deepcopy(d["files"][0]))), "exactly once")
        self.refused(self.capture(lambda d: d["files"].pop()), "exactly once")
        self.refused(self.capture(lambda d: d["files"][1].update(sourcePath="offline/results/benchmark_data.json",
                                                                 url=RAW.format(REV, "benchmark_data.json"),
                                                                 path="/x/benchmark_data.json")), "exactly once")
        self.refused(self.capture(lambda d: d["files"][0].update(sourcePath="../etc/passwd")), "known benchmark")
        self.refused(self.capture(lambda d: d["files"][0].update(sourcePath="offline/results/other.json")), "known benchmark")
        self.refused(self.capture(lambda d: d["files"][0].update(path="/x/pr_labels.json")), "logical name")

    def test_revision_and_url_must_agree(self):
        self.refused(self.capture(lambda d: d["files"][0].update(revision="c" * 40)), "revision differs")
        self.refused(self.capture(lambda d: d["files"][0].update(url=RAW.format("c" * 40, "benchmark_data.json"))), "url does not")
        self.refused(self.capture(lambda d: d["files"][0].update(url="https://evil.example/benchmark_data.json")), "url does not")
        self.write(self.capture())
        with self.assertRaises(BenchmarkError):
            load_pins(self.pins_path, expect_revision="c" * 40)

    def test_malformed_trust_and_descriptive_values(self):
        for upd, text in (({"bytes": True}, "malformed"), ({"bytes": 0}, "malformed"), ({"bytes": "5"}, "malformed"),
                          ({"gitBlobSha": "B" * 40}, "malformed"), ({"sha256": "0" * 64}, "malformed"),
                          ({"capturedAt": "yesterday"}, "capturedAt"), ({"topType": "list"}, "shape"),
                          ({"topCount": 999}, "shape"), ({"topKeys": [1]}, "shape")):
            self.refused(self.capture(lambda d, u=upd: d["files"][0].update(u)), text)

    def test_receipt_is_not_a_pins_file_and_inside_store_refused(self):
        self.refused({"schema": "benchmark-source-import-receipt@1", "sourcePins": "x", "files": []}, "schema must be")
        inside = self.store / "pins.json"
        inside.write_text(json.dumps(self.capture()))
        with self.assertRaises(BenchmarkError):
            load_pins(inside, store_dirs=[self.store])

    def test_cli_verify_pins_on_actual_format_and_tamper(self):
        self.write(self.capture())
        argv = ["verify-pins", "--pins", str(self.pins_path), "--data", str(self.dp), "--labels", str(self.lp),
                "--expect-revision", REV]
        self.assertEqual(main(argv), 0)
        self.lp.write_bytes(self.lp.read_bytes() + b" ")
        self.assertEqual(main(argv), 1)
