"""impact@v19 recording pins (test_agentic_v19 scenarios through test_cross_model_v10.pin_of) of the tree in cwd: the e2e
run with a judge-rule drop, a session out of schema and its re-ask, a tool attempt and its re-ask, and an unavailable
judge. Offline. Used by test_agentic_v20.V19Parity (and run on the pre-change source 1e80171 to make its pins)."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tests.pipeline import test_agentic_v19 as T
from tests.pipeline.helpers import entry
from tests.pipeline.test_cross_model_v10 import pin_of

out = {}


class R(T.V19Rig):
    def fresh(self, name):
        self.out = self.tmp / name
        self.out.mkdir()

    def runTest(self):
        A, Rr = T.A, T.R
        m = self.case12()
        scr, _ = self.run19(m, judged=(0, 1))
        out["e2e"] = pin_of(self.record_v19(m, scr)[0])
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        scr, _ = self.run19(m, session=[*T.cli_bad(A, 0), T.cli(Rr, 0, {"hypotheses": [hl, hb, hs]})])
        self.fresh("o2")
        out["schema_reask"] = pin_of(self.record_v19(m, scr)[0])
        scr, _ = self.run19(m, session=[T.EndToEnd.tool_kill(self, A), T.cli(Rr, 0, {"hypotheses": [hl, hb, hs]})])
        self.fresh("o3")
        out["tool_reask"] = pin_of(self.record_v19(m, scr)[0])
        scr, _ = self.run19(m, judge_entry=entry("JUDGE", "judge", "judge", 0, error={
            "code": "provider-error", "message": "scripted", "retryable": False, "stage": "JUDGE",
            "detail": {"outcome": "rejected-before-processing"}}))
        self.fresh("o4")
        out["judge_unavailable"] = pin_of(self.record_v19(m, scr)[0])


r = unittest.TextTestRunner(stream=open(os.devnull, "w")).run(R())
assert r.wasSuccessful(), r.failures + r.errors
print(json.dumps(out, sort_keys=True))
