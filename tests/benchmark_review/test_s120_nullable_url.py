"""S1-20 independent gate: nullable review pr_url. Invented data only; no product edits."""

import copy
import json

from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.projection import project_metadata, resolve_versions

from tests.benchmark.helpers import Fx, TOOLS
from tests.benchmark.test_projection_cutoff import RULES


class S120Gate(Fx):
    def _case(self, i=0):
        return list(self.data)[i]

    def test_null_url_has_no_effect_on_case_identity_ids_order_and_comments(self):
        url = self._case()
        base = self.source().cases[url]
        self.data[url]["reviews"][1]["pr_url"] = None
        self.data[url]["reviews"][1]["review_comments"].append(
            {"path": None, "line": None, "body": "BODYTEXT summary", "created_at": "2025-02-01T11:00:00Z"})
        self.write_all()
        s = self.source()
        self.assertEqual(list(s.cases), list(self.data))             # roster/order unchanged
        c = s.cases[url]
        self.assertEqual(c.url, url)
        self.assertIsNone(c.reviews[1].pr_url)
        self.assertEqual([r.tool for r in c.reviews], list(TOOLS))
        self.assertEqual([x.id for x in c.reviews[1].comments][:1], [x.id for x in base.reviews[1].comments])
        self.assertEqual(len(c.reviews[1].comments), 2)
        self.assertTrue(c.reviews[1].comments[1].path is None)
        for i in (0, 2, 3):
            self.assertEqual(c.reviews[i], base.reviews[i])

    def test_nested_url_differing_from_case_url_does_not_change_case_identity(self):
        url = self._case()
        self.data[url]["reviews"][0]["pr_url"] = "https://other.example/x/pull/9"
        self.write_all()
        c = self.source().cases[url]
        self.assertEqual(c.url, url)
        self.assertEqual(c.reviews[0].pr_url, "https://other.example/x/pull/9")

    def test_empty_string_url_stays_empty_string_not_null(self):
        url = self._case()
        self.data[url]["reviews"][0]["pr_url"] = ""
        self.write_all()
        self.assertEqual(self.source().cases[url].reviews[0].pr_url, "")

    def test_ids_distinguish_tools_when_all_urls_null(self):
        url = self._case()
        for r in self.data[url]["reviews"]:
            r["pr_url"] = None
        self.write_all()
        ids = [r.comments[0].id for r in self.source().cases[url].reviews]
        self.assertEqual(len(set(ids)), len(TOOLS))
        self.assertEqual(ids, [r.comments[0].id for r in self.source().cases[url].reviews])

    def test_every_case_all_null_loads_and_projects_without_text(self):
        for e in self.data.values():
            for r in e["reviews"]:
                r["pr_url"] = None
        self.write_all()
        s = self.source()
        self.assertEqual(len(s.cases), len(self.data))
        proj = project_metadata(s)
        self.assertTrue(all(r["prUrl"] is None for c in proj["cases"] for r in c["reviews"]))
        txt = json.dumps(proj)
        for needle in ("BODYTEXT", "GOLDTEXT", "TITLETEXT"):
            self.assertNotIn(needle, txt)

    def test_version_resolution_with_null_links_resolves_and_keeps_all_cases(self):
        url = self._case()
        self.data[url]["reviews"][3]["pr_url"] = None   # greptile-v1 of one case
        self.write_all()
        proj = project_metadata(self.source())
        r = resolve_versions(proj, copy.deepcopy(RULES))
        self.assertEqual(r["status"], "resolved")
        self.assertIn(url, r["commonEligibleSet"])       # null link is not a skip
        self.assertEqual(r["omitted"], {})
        json.dumps(r)

    def test_skip_rule_by_url_does_not_match_null_link_but_case_url_rule_still_works(self):
        url = self._case()
        self.data[url]["reviews"][3]["pr_url"] = None
        self.write_all()
        proj = project_metadata(self.source())
        rules = copy.deepcopy(RULES)
        rules["families"]["greptile"]["skipped"] = [{"tool": "greptile-v1", "prUrl": "https://x/y"}]
        self.assertIn(url, resolve_versions(proj, rules)["commonEligibleSet"])
        rules["families"]["greptile"]["skipped"] = [{"tool": "greptile-v1", "prUrl": url}]
        r = resolve_versions(proj, rules)
        self.assertNotIn(url, r["commonEligibleSet"])

    def test_skip_rule_with_null_prurl_must_not_silently_skip_null_links(self):
        """A skipped rule needs a real link. Null must be refused or at least never match a null review."""
        url = self._case()
        self.data[url]["reviews"][3]["pr_url"] = None
        self.write_all()
        proj = project_metadata(self.source())
        rules = copy.deepcopy(RULES)
        rules["families"]["greptile"]["skipped"] = [{"tool": "greptile-v1", "prUrl": None}]
        try:
            r = resolve_versions(proj, rules)
        except BenchmarkError:
            return
        self.assertIn(url, r["commonEligibleSet"], "null skip rule matched a null review link")

    def test_skip_rule_with_non_string_prurl_is_refused(self):
        proj = project_metadata(self.source())
        for bad in (3, True, ["a"], {"a": 1}):
            rules = copy.deepcopy(RULES)
            rules["families"]["greptile"]["skipped"] = [{"tool": "greptile-v1", "prUrl": bad}]
            with self.subTest(bad=bad), self.assertRaises(BenchmarkError):
                resolve_versions(proj, rules)
