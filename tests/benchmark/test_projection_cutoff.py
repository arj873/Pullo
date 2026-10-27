import json

from reviewer.benchmark.cutoff import attestation_binding, resolve_cutoff, select_cases
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.loader import load_proposal
from reviewer.benchmark.projection import project_metadata, resolve_versions

from .helpers import Fx, GOLD, REPOS

RULES = {"schema": "benchmark-version-rules@1", "families": {
    "cubic": {"prefix": "cubic", "superseded": ["cubic-v1"], "skipped": [], "source": {"blob": "x", "quote": "q"}},
    "coderabbit": {"prefix": "coderabbit", "superseded": [], "skipped": [], "source": {"blob": "x", "quote": "q"}},
    "greptile": {"prefix": "greptile", "superseded": [], "skipped": [], "source": {"blob": "x", "quote": "q"}}}}


def proof(url, repo, **over):
    d = {"schema": "benchmark-cutoff-proof@1", "originalUrl": url, "resolvedRepo": repo, "asOfBase": "1" * 40,
         "asOfHead": "2" * 40, "mergeBase": "1" * 40, "headCommittedAt": "2025-01-31T00:00:00Z",
         "evidence": [{"kind": "commit-time", "source": "fixture-git-log", "observedAt": "t", "value": "v"},
                      {"kind": "review-time", "source": "benchmark-comments", "observedAt": "t", "value": "v"}]}
    d.update(over)
    return d


def good_proof(url):
    repo = url.split("github.com/")[1].rsplit("/pull", 1)[0]
    p = proof(url, repo)
    if "ai-code-review-evaluation" in url:
        p["evidence"].append({"kind": "fork-mapping", "source": "fixture-mapping", "observedAt": "t", "value": "orig"})
    return p


def admit(p):
    """Test plays root: a separate admission bound to this exact proof."""
    return {"schema": "benchmark-cutoff-admission@1", **attestation_binding(p), "admittedBy": "root",
            "admittedAt": "2026-10-26T04:00:00Z", "decisionRef": "fixture-recheck"}


class Projection(Fx):
    def setUp(self):
        super().setUp()
        self.proj = project_metadata(self.source())

    def test_projection_is_metadata_only(self):
        text = json.dumps(self.proj)
        for t, _, _ in GOLD[1]:
            self.assertNotIn(t, text)
        self.assertNotIn("BODYTEXT", text)
        self.assertNotIn("TITLETEXT", text)
        self.assertNotIn("a.py", text)
        c = self.proj["cases"][0]
        self.assertEqual(c["reviews"][0]["commentCount"], 1)
        self.assertEqual(c["reviews"][0]["firstCreatedAt"], "2025-02-01T10:00:00Z")
        self.assertEqual(self.proj["excludedFixtures"], ["https://example/pr"])

    def test_versions_unresolved_without_rules_or_when_ambiguous(self):
        r = resolve_versions(self.proj, None)
        self.assertEqual(r["status"], "unresolved")
        self.assertIsNone(r["commonEligibleSet"])
        amb = json.loads(json.dumps(RULES))
        amb["families"]["cubic"]["superseded"] = []
        r = resolve_versions(self.proj, amb)
        self.assertEqual(r["status"], "unresolved")
        self.assertIsNone(r["families"]["cubic"]["chosen"])
        self.assertEqual(r["families"]["cubic"]["candidates"], ["cubic-v1", "cubic-v2"])

    def test_versions_resolved_common_set_and_omissions_retained(self):
        rules = json.loads(json.dumps(RULES))
        skipped_url = self.proj["cases"][0]["url"]
        rules["families"]["greptile"]["skipped"] = [{"tool": "greptile-v1", "prUrl": skipped_url}]
        r = resolve_versions(self.proj, rules)
        self.assertEqual(r["status"], "resolved")
        self.assertEqual(r["chosen"], {"cubic": "cubic-v2", "coderabbit": "coderabbit-v1", "greptile": "greptile-v1"})
        self.assertEqual(len(r["attempted"]), 6)
        self.assertNotIn(skipped_url, r["commonEligibleSet"])
        self.assertIn(skipped_url, r["omitted"])
        self.assertEqual(len(r["commonEligibleSet"]) + len(r["omitted"]), 6)

    def test_bad_rules_refused(self):
        with self.assertRaises(BenchmarkError):
            resolve_versions(self.proj, {"schema": "benchmark-version-rules@1", "families": {"cubic": {}}})


class Cutoff(Fx):
    def setUp(self):
        super().setUp()
        self.proj = project_metadata(self.source())
        self.by = {c["url"]: c for c in self.proj["cases"]}
        self.prop = load_proposal(self.pp)

    def one(self, repo_key="alpha"):
        return self.prop.universe[repo_key][0]

    def test_unproven_without_or_with_weak_proof(self):
        u = self.one()
        self.assertEqual(resolve_cutoff(u, None, self.by[u])["status"], "unproven")
        self.assertEqual(resolve_cutoff(u, good_proof(u), self.by[u])["status"], "attested")
        self.assertEqual(resolve_cutoff(u, good_proof(u), self.by[u], admit(good_proof(u)))["status"], "proven")
        bad = good_proof(u)
        bad["evidence"].append({"kind": "upstream-pin", "source": "current-pr-head", "observedAt": "t", "value": "v"})
        self.assertIn("current-pr-head", " ".join(resolve_cutoff(u, bad, self.by[u])["reasons"]))
        self.assertEqual(resolve_cutoff(u, bad, self.by[u])["status"], "unproven")

    def test_failures_each_reason(self):
        u = self.one()
        for mut, frag in ((lambda p: p.update(asOfHead="abc"), "asOfHead"),
                          (lambda p: p.update(headCommittedAt="2025-03-01T00:00:00Z"), "after the earliest"),
                          (lambda p: p.update(evidence=p["evidence"][:1]), "review-time"),
                          (lambda p: p.update(originalUrl="https://x"), "different original"),
                          (lambda p: p.update(resolvedRepo="other/repo"), "fork-mapping")):
            p = good_proof(u)
            mut(p)
            r = resolve_cutoff(u, p, self.by[u])
            self.assertEqual(r["status"], "unproven", frag)
            self.assertIn(frag, " ".join(r["reasons"]))

    def test_evaluation_fork_needs_mapping(self):
        u = self.one("gamma")
        p = good_proof(u)
        p["evidence"] = [e for e in p["evidence"] if e["kind"] != "fork-mapping"]
        self.assertEqual(resolve_cutoff(u, p, self.by[u])["status"], "unproven")

    def test_selection_no_proofs_nothing_reproducible_and_no_fabrication(self):
        sel = select_cases(self.prop, self.proj, {})
        self.assertEqual((sel["dev"], sel["frozen"]), ([], []))
        self.assertFalse(sel["allReproducible"])
        self.assertEqual(len(sel["exclusions"]), 6)
        self.assertFalse(sel["scoresRead"])

    def test_selection_successor_and_record_before_scores(self):
        proofs = {u: good_proof(u) for us in self.prop.universe.values() for u in us}
        adm = {u: admit(p) for u, p in proofs.items()}
        sel = select_cases(self.prop, self.proj, proofs, adm)
        self.assertTrue(sel["allReproducible"])
        self.assertFalse(sel["differsFromDeclared"])
        first = self.prop.universe["alpha"][0]
        del proofs[first]
        sel = select_cases(self.prop, self.proj, proofs, adm)
        self.assertTrue(sel["differsFromDeclared"])
        self.assertIn(self.prop.universe["alpha"][1], sel["dev"])        # successor takes the dev slot
        self.assertNotIn(self.prop.universe["alpha"][1], sel["frozen"])
        self.assertEqual([e["url"] for e in sel["exclusions"]], [first])
        self.assertEqual(sel["coverage"]["reproducible"], 5)
        self.assertEqual(sel["coverage"]["universe"], 6)
