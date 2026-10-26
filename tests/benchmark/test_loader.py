import json
import os

from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.jsonio import parse_json
from reviewer.benchmark.loader import load_source
from reviewer.benchmark.pins import load_pins, pin_for, verify_file

from .helpers import Fx, make_data, make_labels, make_proposal


class Loader(Fx):
    def test_loads_and_reports_fixture_without_scoring_it(self):
        s = self.source()
        r = s.report()
        self.assertEqual((r["cases"], r["labelEntries"], r["scoredCaseCount"]), (6, 7, 6))
        self.assertEqual(r["excludedFixtures"], ["https://example/pr"])
        self.assertNotIn("https://example/pr", s.cases)
        self.assertEqual(r["goldenCountDisagreements"], [])
        c = next(iter(s.cases.values()))
        self.assertTrue(c.golden[0].id.startswith("gold:0:"))
        self.assertEqual({g.category for g in c.golden}, {"bug", "perf", "style", "security"})

    def test_pr_labels_without_fixture_also_loads_but_extra_url_refused(self):
        self.write_all(labels=make_labels(self.data, fixture=False))
        self.assertEqual(self.source().report()["excludedFixtures"], [])
        lab = make_labels(self.data)
        lab["https://example/other"] = {}
        self.write_all(labels=lab)
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertEqual(cm.exception.code, "roster")

    def test_missing_case_in_data_or_labels_refused(self):
        d = dict(self.data)
        d.pop(next(iter(d)))
        self.write_all(data=d, labels=make_labels(self.data))
        with self.assertRaises(BenchmarkError):
            self.source()
        lab = make_labels(self.data)
        lab.pop(next(iter(self.data)))
        self.write_all(labels=lab)
        with self.assertRaises(BenchmarkError):
            self.source()

    def test_tamper_same_length_size_and_blob(self):
        raw = bytearray(self.dp.read_bytes())
        i = raw.index(b"GOLDTEXT")
        raw[i] = ord("g")
        self.dp.write_bytes(bytes(raw))
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertEqual(cm.exception.code, "tamper")
        self.dp.write_bytes(bytes(raw) + b" ")
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertIn(cm.exception.code, ("size", "tamper"))

    def test_blob_id_checked_independently_of_sha256(self):
        p = self.pins()
        p["files"][0]["gitBlobSha"] = "b" * 40
        self.pins_path.write_text(json.dumps(p))
        with self.assertRaises(BenchmarkError) as cm:
            verify_file(self.dp, pin_for(load_pins(self.pins_path), "benchmark_data.json"))
        self.assertIn("Git blob", cm.exception.message)

    def test_pins_must_be_external_and_revision_checked(self):
        inside = self.store / "pins.json"
        inside.write_text(self.pins_path.read_text())
        with self.assertRaises(BenchmarkError):
            load_pins(inside, store_dirs=[self.store])
        with self.assertRaises(BenchmarkError):
            load_pins(self.pins_path, expect_revision="c" * 40)
        self.pins_path.write_text(json.dumps(self.pins(revision="zz")))
        with self.assertRaises(BenchmarkError):
            load_pins(self.pins_path)
        self.pins_path.write_text(json.dumps(self.pins(extra=1)) if False else json.dumps({"schema": "nope"}))
        with self.assertRaises(BenchmarkError):
            load_pins(self.pins_path)

    def test_symlinked_source_refused(self):
        real = self.tmp / "real.json"
        real.write_bytes(self.dp.read_bytes())
        self.dp.unlink()
        os.symlink(real, self.dp)
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertEqual(cm.exception.code, "io")

    def test_proposal_revision_rank_and_partition_checks(self):
        p = make_proposal()
        p["sourceRevision"] = "d" * 40
        self.write_all(proposal=p)
        with self.assertRaises(BenchmarkError):
            self.source()
        p = make_proposal()
        first = next(iter(p["rankedUniverse"]))
        p["rankedUniverse"][first].reverse()
        self.write_all(proposal=p)
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertIn("rank", cm.exception.message)
        p = make_proposal()
        p["rankedUniverse"][first][0]["urlSha256"] = "0" * 64
        self.write_all(proposal=p)
        with self.assertRaises(BenchmarkError):
            self.source()

    def test_strict_json_and_shape(self):
        with self.assertRaises(BenchmarkError):
            parse_json(b'{"a":1,"a":2}')
        with self.assertRaises(BenchmarkError):
            parse_json(b'{"a":NaN}')
        with self.assertRaises(BenchmarkError):
            parse_json(b"[" * 30 + b"]" * 30)
        d = make_data(self.proposal)
        u = next(iter(d))
        d[u]["golden_comments"][0]["category"] = "vibes"
        self.write_all(data=d)
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertEqual(cm.exception.code, "category")
        d = make_data(self.proposal)
        d[u]["unexpected"] = 1
        self.write_all(data=d)
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertEqual(cm.exception.code, "shape")
