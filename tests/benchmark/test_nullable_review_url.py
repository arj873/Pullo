"""Nullable review pr_url: literal null is preserved end to end; other non-string types are refused. Invented data only."""

from reviewer.benchmark.errors import BenchmarkError
import copy

from reviewer.benchmark.projection import project_metadata, resolve_versions

from .helpers import Fx, TOOLS
from .test_projection_cutoff import RULES


class NullableReviewUrl(Fx):
    def _null_two(self):
        url = next(iter(self.data))
        self.data[url]["reviews"][0]["pr_url"] = None
        self.data[url]["reviews"][2]["pr_url"] = None
        self.write_all()
        return url

    def test_null_loads_as_literal_none_with_everything_else_intact(self):
        url = self._null_two()
        c = self.source().cases[url]
        self.assertEqual([r.tool for r in c.reviews], list(TOOLS))
        self.assertEqual([r.pr_url for r in c.reviews], [None, url, None, url])
        for r in c.reviews:
            self.assertEqual(len(r.comments), 1)
            self.assertIsNot(r.pr_url, "")
            self.assertNotEqual(r.pr_url, "None")

    def test_projection_keeps_null_text_free_and_counts(self):
        url = self._null_two()
        proj = project_metadata(self.source())
        rev = next(c for c in proj["cases"] if c["url"] == url)["reviews"]
        self.assertEqual([r["prUrl"] for r in rev], [None, url, None, url])
        self.assertEqual([r["commentCount"] for r in rev], [1, 1, 1, 1])
        self.assertNotIn("BODYTEXT", repr(proj))
        self.assertNotIn("GOLDTEXT", repr(proj))

    def test_comment_ids_ignore_review_url_and_stay_isolated_per_tool(self):
        url = self._null_two()
        ids = [r.comments[0].id for r in self.source().cases[url].reviews]
        self.assertEqual(len(set(ids)), 4)
        before = self.source().cases[url]
        self.data[url]["reviews"][0]["pr_url"] = url
        self.write_all()
        after = self.source().cases[url]
        self.assertEqual([r.comments[0].id for r in before.reviews], [r.comments[0].id for r in after.reviews])

    def test_missing_key_and_non_string_types_still_refused(self):
        url = next(iter(self.data))
        for bad in (True, False, 0, 3, 1.5, [], ["x"], {}, {"a": 1}):
            with self.subTest(bad=bad):
                self.data[url]["reviews"][0]["pr_url"] = bad
                self.write_all()
                with self.assertRaises(BenchmarkError):
                    self.source()
        self.data[url]["reviews"][0].pop("pr_url")
        self.write_all()
        with self.assertRaises(BenchmarkError):
            self.source()

    def test_other_review_fields_still_must_be_strings(self):
        url = next(iter(self.data))
        for key in ("tool", "repo_name"):
            self.data[url]["reviews"][0][key] = None
            self.write_all()
            with self.subTest(key=key), self.assertRaises(BenchmarkError):
                self.source()
            self.data[url]["reviews"][0][key] = "ok-" + key

    def test_skipped_entries_need_string_tool_and_nonempty_string_prurl(self):
        url = self._null_two()
        proj = project_metadata(self.source())
        fam = next(iter(RULES["families"]))
        for bad in ({"tool": TOOLS[0], "prUrl": None}, {"tool": TOOLS[0], "prUrl": ""}, {"tool": TOOLS[0], "prUrl": 3},
                    {"tool": TOOLS[0], "prUrl": []}, {"tool": TOOLS[0], "prUrl": {}}, {"tool": None, "prUrl": url},
                    {"tool": [], "prUrl": url}, {"tool": {}, "prUrl": url}):
            with self.subTest(bad=bad):
                rules = copy.deepcopy(RULES)
                rules["families"][fam]["skipped"] = [bad]
                with self.assertRaises(BenchmarkError) as cm:
                    resolve_versions(proj, rules)
                self.assertEqual(cm.exception.code, "rules")
        rules = copy.deepcopy(RULES)
        rules["families"][fam]["skipped"] = [{"tool": TOOLS[0], "prUrl": url}]
        resolve_versions(proj, rules)
