"""impact@v24 recording pins (test_seeded_v24 scenarios through test_cross_model_v10.pin_of) of the tree in cwd: the seeded e2e
run (reuse mode: drops, a same-lane merge, two verifiers, JUDGE) and the live-mode one-seed run. Offline.
Used by test_union_v25.V24Parity (and run on the pre-change source 2bae112, cap150's ccfilter-v24 head, to make its pins)."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tests.pipeline import test_dual_v21 as T
from tests.pipeline import test_seeded_v24 as S
from tests.pipeline.helpers import judge, script
from tests.pipeline.test_cross_model_v10 import pin_of
from tests.pipeline.test_impact_pipeline import w

out = {}


class R(S.V24Rig):
    def fresh(self, name):
        self.out = self.tmp / name
        self.out.mkdir()

    def runTest(self):
        m = self.case12()
        self.seed = S.seed_doc(S.ITEMS)
        scr, _ = self.run24(m)
        out["e2e"] = pin_of(self.record_v24(m, scr)[0])
        self.seed = S.seed_doc(S.ITEMS[:1], mode="live")
        self.fresh("o2")
        out["live"] = pin_of(self.record_v24(m, script(T.vcc("verifier-01", m, path="src/lib.py", line=1),
                                                       judge(w([S.sid(0, S.ITEMS[0])]))))[0])


r = unittest.TextTestRunner(stream=open(os.devnull, "w")).run(R())
assert r.wasSuccessful(), r.failures + r.errors
print(json.dumps(out, sort_keys=True))
