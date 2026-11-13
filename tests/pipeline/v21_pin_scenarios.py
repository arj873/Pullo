"""impact@v21 recording pins (test_dual_v21 scenarios through test_cross_model_v10.pin_of) of the tree in cwd: the e2e run
with a union merge and a judge-rule drop, and a run whose judge merges two findings of one issue-key@2 group. Offline.
Used by test_precision_v22.V21Parity (and run on the pre-change source 2eff0f8 to make its pins)."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tests.pipeline import test_dual_v21 as T
from tests.pipeline.helpers import hyp, judge
from tests.pipeline.test_cross_model_v10 import pin_of
from tests.pipeline.test_coverage_v12 import hid
from tests.pipeline.test_impact_pipeline import w

out = {}


class R(T.V21Rig):
    def fresh(self, name):
        self.out = self.tmp / name
        self.out.mkdir()

    def runTest(self):
        m = self.case12()
        scr, _ = self.run21(m, judged=("l", "b"))
        out["e2e"] = pin_of(self.record_v21(m, scr)[0])
        hl, hs = self.h_lib(m), self.h_svc(m)
        h2 = hyp(m, "src/svc.py", 2, claim="the sum of an empty list is one, not zero, because total starts at one",
                 category="bug", impact="incorrect-result", severity="P2", evidence=[m.cite("src/svc.py", 2)])
        ids = {"l": hid(T.G, 0, hl), "s": hid(T.G, 1, hs), "s2": hid(T.G, 2, h2), "b": hid(T.P, 1, self.h_b(m))}
        scr, _ = self.run21(m, ag=[T.cli(T.G, 0, {"hypotheses": [hl, hs, h2]})],
                            verifiers=[T.vcc(f"verifier-0{n}", m, path=p, line=ln) for n, (p, ln) in enumerate(
                                (("src/lib.py", 1), ("src/handlers/b.py", 2), ("src/svc.py", 2), ("src/svc.py", 2)), 1)],
                            judge_entry=judge(w([ids["l"]]), w([ids["b"]]), w([ids["s"], ids["s2"]], body="Main.\n\nAlso, x.")))
        self.fresh("o2")
        out["judge_merge"] = pin_of(self.record_v21(m, scr)[0])


r = unittest.TextTestRunner(stream=open(os.devnull, "w")).run(R())
assert r.wasSuccessful(), r.failures + r.errors
print(json.dumps(out, sort_keys=True))
