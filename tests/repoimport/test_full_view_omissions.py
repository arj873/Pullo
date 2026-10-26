"""S1-10 / S1-04-review N4: `full_view_of` is omission-aware. REAL importer over local Git fixtures (no network)."""

from reviewer.repoimport import full_view_of, import_repository
from reviewer.tools import full_view, import_view, omissions_from_records

from .helpers import Tmp, git


class FullViewOf(Tmp):
    def imports(self, head_files, base_files=None):
        base_files = base_files or {"src/a.py": "x = 1\n"}
        out = []
        for files in (base_files, head_files):
            w, sha = self.fixture(files, name=f"src{len(out)}")
            out.append(import_repository(self.remote(w), sha, self.store / f"s{len(out)}"))
        return out

    def test_an_import_with_omissions_is_never_reported_as_full_repository(self):
        base, head = self.imports({"src/a.py": "x = 2\n", "blob.bin": b"\x00\x01\x02binary"})
        self.assertEqual((base.record["omissions"]["counts"], head.record["omissions"]["counts"]), ({}, {"binary": 1}))
        view = full_view_of(base, head)
        cov = view.coverage()
        self.assertEqual((cov["scope"], cov["fullRepositoryCoverage"]), ("repository-with-omissions", False))
        self.assertEqual(cov["omissions"], {"base": {}, "head": {"binary": 1}})
        self.assertTrue(view.omitted and view.approximate)
        self.assertIn("WITH OMISSIONS", view.note())

    def test_it_equals_import_view_over_the_records(self):
        base, head = self.imports({"src/a.py": "x = 2\n", "blob.bin": b"\x00\x01\x02binary"})
        want = import_view(base.root, base.manifest, head.root, head.manifest,
                           omissions_from_records(base.record, head.record))
        self.assertEqual(full_view_of(base, head).coverage(), want.coverage())

    def test_a_complete_import_is_unchanged_full_repository(self):
        base, head = self.imports({"src/a.py": "x = 2\n"})
        view = full_view_of(base, head)
        plain = full_view(base.root, base.manifest, head.root, head.manifest)
        self.assertEqual(view.coverage(), plain.coverage())
        self.assertEqual(view.coverage()["scope"], "full-repository")
        self.assertFalse(view.omitted)
        self.assertEqual(view.note(), plain.note())

    def test_the_helper_still_takes_two_imports_and_returns_a_view(self):
        base, head = self.imports({"src/a.py": "x = 2\n"})
        self.assertEqual(type(full_view_of(base, head)).__name__, "View")
