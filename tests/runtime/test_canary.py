import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from reviewer.runtime import canary
from reviewer.runtime.envfile import Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.runtime.common import FAKE_KEY, SONNET, FakeTransport, completion
from tests.gateway import helpers as H


class Canary(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        d = Path(self._t.name)
        self.state = d / "state"
        self.auth = d / "auth.json"
        self.auth.write_text(json.dumps({**H.AUTH_DOC, "id": "or-trial", "providers": ["anthropic"], "models": [SONNET],
                                         "maxUsdMicrosPerRun": 4_000_000, "maxUsdMicrosTotal": 50_000_000, "purpose": "t"}))
        os.chmod(self.auth, 0o600)

    def run_main(self, *extra, transport=None):
        out = io.StringIO()
        rc = canary.main(["--auth", str(self.auth), "--state-dir", str(self.state), *extra], transport=transport,
                         key_loader=lambda *a, **k: Secret(FAKE_KEY), out=out)
        return rc, json.loads(out.getvalue())

    def test_dry_run_sends_nothing_and_reads_no_key(self):
        def boom(*a, **k):
            raise AssertionError("dry run must not load a key")
        out = io.StringIO()
        rc = canary.main(["--auth", str(self.auth), "--state-dir", str(self.state)], key_loader=boom, out=out)
        rep = json.loads(out.getvalue())
        self.assertEqual((rc, rep["live"], rep["ok"]), (0, False, False))
        self.assertEqual(len(rep["requestBytes"]), 1)
        self.assertNotIn(FAKE_KEY, out.getvalue())
        self.assertEqual(list(self.state.iterdir()), [])          # durable book/ledger untouched by a dry run
        self.assertEqual(rep["gateway"]["liveCalls"], 1)          # exercised the real gateway path with a recording transport

    def test_live_path_with_fake_transport_reports_without_secrets(self):
        keyinfo = json.dumps({"data": {"limit": 50, "usage": 0, "limit_remaining": 50}}).encode()
        after = json.dumps({"data": {"limit": 50, "usage": 0.004, "limit_remaining": 49.996}}).encode()
        tr = FakeTransport(keyinfo, completion(), after)
        rc, rep = self.run_main("--live", "--env", "ignored", transport=tr)
        self.assertEqual((rc, rep["ok"], rep["resolvedModel"]), (0, True, SONNET))
        self.assertEqual((rep["keyBefore"]["usage"], rep["keyAfter"]["usage"]), ("0", "0.004"))
        self.assertEqual([r.path for r in tr.requests], ["/api/v1/key", "/api/v1/chat/completions", "/api/v1/key"])
        self.assertEqual(rep["runtimeLedger"]["knownUsdMicros"], 4000)
        self.assertTrue(Path(rep["trace"]).exists())
        for p in self.state.iterdir():
            self.assertNotIn(FAKE_KEY, p.read_text())

    def test_live_failure_exit_code(self):
        rc, rep = self.run_main("--live", "--env", "x", transport=FakeTransport(b'{"data":{}}', HttpResponse(402, {}, b"{}"), b'{"data":{}}'))
        self.assertEqual((rc, rep["ok"], rep["error"]["code"]), (1, False, "provider-error"))
        self.assertEqual(rep["runtimeLedger"]["committedUsdMicros"], 0)       # a 402 is a documented non-billed rejection

    def test_request_is_tiny(self):
        p = canary.canary_profile()
        self.assertEqual(p["roles"]["investigator"]["params"], {"maxOutputTokens": 300})
        self.assertLessEqual(canary.CANARY_BUDGET_MICROS, 100_000)


if __name__ == "__main__":
    unittest.main()
