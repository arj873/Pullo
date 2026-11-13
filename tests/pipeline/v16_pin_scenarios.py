"""impact@v16 recording pins (test_whole_v16 scenarios through test_cross_model_v10.pin_of) of the tree in cwd: the e2e
run, a reviewer schema re-ask, a verifier still out of schema after its re-ask, and a limit-ended reviewer re-ask.
Offline. Used by test_agentic_v19.V16Parity (and /var/tmp/pullo-cap150/v16work/pin_v16.py on the pre-change source)."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tests.pipeline import test_whole_v16 as T
from tests.pipeline.test_cross_model_v10 import pin_of

out = {}


class R(T.V16Rig):
    def runTest(self):
        A, Rr = T.A, T.R
        m = self.case12()
        scr, _ = self.e2e(m)
        out["e2e"] = pin_of(self.record_v16(m, scr)[0])
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        e = [T.turn(A, 0, [T.rf("src/use.py", 1, 7)]), *T.bad_turn(A, 1)] + self.reviewer(Rr, [hl, hb, hs])
        e += [T.vdone("verifier-01", m, path="src/lib.py", line=1), T.vdone("verifier-02", m, path="src/handlers/b.py", line=2),
              T.vdone("verifier-03", m, path="src/svc.py", line=2),
              T.judge(T.w([T.hid(Rr, 0, hl)]), T.w([T.hid(Rr, 1, hb)]), T.w([T.hid(Rr, 2, hs)]))]
        self.out = self.tmp / "o2"; self.out.mkdir()
        out["reviewer_reask"] = pin_of(self.record_v16(m, T.script(*e))[0])
        scr, _ = self.e2e(m, verifiers=[*T.bad_turn("verifier-01", 0, "VERIFY", "verifier"),
                                        *T.bad_turn("verifier-01-reask", 0, "VERIFY", "verifier"),
                                        T.vdone("verifier-02", m, path="src/handlers/b.py", line=2),
                                        T.vdone("verifier-03", m, path="src/svc.py", line=2)], judged=(1, 2))
        self.out = self.tmp / "o3"; self.out.mkdir()
        out["verifier_note"] = pin_of(self.record_v16(m, scr)[0])
        paths = ["src/use.py", "src/lib.py", "src/svc.py", "src/handlers/a.py", "src/handlers/b.py", "src/handlers/c.py"]
        e = [T.turn(A, k, [T.rf(p, 1 + k) for p in paths]) for k in range(3)] + [T.final(Rr, 0, hl)]
        e += [T.vdone("verifier-01", m, path="src/lib.py", line=1), T.judge(T.w([T.hid(Rr, 0, hl)]))]
        self.out = self.tmp / "o4"; self.out.mkdir()
        out["limit_reask"] = pin_of(self.record_v16(m, T.script(*e))[0])


r = unittest.TextTestRunner(stream=open(os.devnull, "w")).run(R())
assert r.wasSuccessful(), r.failures + r.errors
print(json.dumps(out, sort_keys=True))
