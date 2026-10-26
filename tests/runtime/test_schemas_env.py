import json
import os
import stat
import unittest

from reviewer.runtime import EnvFileError, Secret, load_openrouter_key, schemas
from tests.runtime.common import FAKE_KEY
import tempfile
from pathlib import Path

STRIPPED = {"minLength", "maxLength", "minimum", "maximum", "pattern", "uniqueItems", "minItems", "maxItems",
            "x-invariants", "$ref", "oneOf", "const"}


def keys(o, acc):
    if isinstance(o, dict):
        acc.update(o)
        for v in o.values():
            keys(v, acc)
    elif isinstance(o, list):
        for v in o:
            keys(v, acc)
    return acc


class Projection(unittest.TestCase):
    def test_no_unsupported_keywords_in_either_flavor(self):
        for name in ("InvestigatorOutput", "VerifierOutput", "JudgeOutput"):
            for fl in ("anthropic", "openai-strict"):
                bad = keys(schemas.provider_schema(name, fl), set()) & STRIPPED
                self.assertFalse(bad, (name, fl, bad))

    def test_strict_flavor_requires_every_key_and_closes_objects(self):
        def walk(n):
            if isinstance(n, dict):
                if "properties" in n:
                    self.assertEqual(set(n["required"]), set(n["properties"]))
                    self.assertIs(n["additionalProperties"], False)
                for v in n.values():
                    walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
        for name in ("InvestigatorOutput", "VerifierOutput", "JudgeOutput"):
            walk(schemas.provider_schema(name, "openai-strict"))

    def test_projection_is_deterministic_snapshot(self):
        self.assertEqual(schemas.schema_bytes("JudgeOutput", "anthropic"), schemas.schema_bytes("JudgeOutput", "anthropic"))
        snap = schemas.projection_snapshot()
        self.assertEqual(len(snap), 10)                          # 3 plain role schemas + 2 Turn envelopes, two flavors each

    def test_optional_nulls_stripped_then_authoritative_validation(self):
        hyp = {"claim": "c", "category": "bug", "suspectedSeverity": "P1", "impact": "crash",
               "location": {"path": "a.py", "line": 1, "endLine": None},
               "evidence": [{"kind": "tool-ref", "toolCallId": "tool_" + "1" * 16, "index": None, "note": None}],
               "mechanism": None, "reach": None, "confidence": None}
        out = {"hypotheses": [hyp]}
        norm = schemas.normalize_output("InvestigatorOutput", out, "openai-strict")
        self.assertNotIn("mechanism", norm["hypotheses"][0])
        self.assertNotIn("endLine", norm["hypotheses"][0]["location"])
        self.assertNotIn("index", norm["hypotheses"][0]["evidence"][0])
        self.assertEqual(schemas.local_issues("InvestigatorOutput", norm), [], schemas.local_issues("InvestigatorOutput", norm))
        # the raw nulls would be rejected by the authoritative validator
        self.assertTrue(schemas.local_issues("InvestigatorOutput", out))

    def test_authoritative_validator_catches_what_projection_dropped(self):
        long = {"comments": [{"findingIds": ["hyp_" + "a" * 16], "title": "t" * 500, "body": "b"}]}
        self.assertTrue(schemas.local_issues("JudgeOutput", long))


class Env(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.d = Path(self._t.name)

    def write(self, text, mode=0o600, name=".env"):
        p = self.d / name
        p.write_text(text)
        os.chmod(p, mode)
        return p

    def test_parses_quoted_and_plain_and_ignores_other_keys(self):
        for line in (f"openrouter_key={FAKE_KEY}", f'openrouter_key="{FAKE_KEY}"', f"openrouter_key = '{FAKE_KEY}'"):
            p = self.write("# c\nOTHER=zzz\n" + line + "\n")
            self.assertEqual(load_openrouter_key(p).reveal(), FAKE_KEY)

    def test_secret_never_shows(self):
        s = Secret(FAKE_KEY)
        for f in (repr, str, format):
            self.assertNotIn(FAKE_KEY, f(s))
        self.assertNotIn(FAKE_KEY, f"{s!r} {s}")
        self.assertEqual(s.scrub(f"x {FAKE_KEY} y"), "x [REDACTED:runtime-key] y")
        import copy, pickle
        for fn in (pickle.dumps, copy.copy, copy.deepcopy):
            with self.assertRaises(TypeError):
                fn(s)

    def test_refusals_never_echo_content(self):
        cases = {"loose mode": dict(text=f"openrouter_key={FAKE_KEY}\n", mode=0o644),
                 "missing key": dict(text=f"other={FAKE_KEY}\n"),
                 "duplicate": dict(text=f"openrouter_key={FAKE_KEY}\nopenrouter_key={FAKE_KEY}\n"),
                 "short": dict(text="openrouter_key=abc\n")}
        for why, kw in cases.items():
            with self.subTest(why), self.assertRaises(EnvFileError) as cm:
                load_openrouter_key(self.write(**kw))
            self.assertNotIn(FAKE_KEY, str(cm.exception))
            self.assertNotIn("abc", str(cm.exception)) if why == "short" else None

    def test_symlink_oversize_and_content_root_refused(self):
        p = self.write(f"openrouter_key={FAKE_KEY}\n")
        link = self.d / "link"
        link.symlink_to(p)
        with self.assertRaises(EnvFileError):
            load_openrouter_key(link)
        big = self.write("#" + "x" * 70000 + "\n", name="big")
        with self.assertRaises(EnvFileError):
            load_openrouter_key(big)
        with self.assertRaises(EnvFileError):
            load_openrouter_key(p, forbidden_roots=[self.d])
        with self.assertRaises(EnvFileError):
            load_openrouter_key(self.d / "nope")


if __name__ == "__main__":
    unittest.main()
