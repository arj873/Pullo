"""DOGFOOD-CONTROL-HOST-02 independent gate. REAL composition (check_options -> config -> prepare -> auth/state/key ->
run_review -> RecordBackend/ReplayBackend) with a FAKE OpenRouter transport and a recording fake key loader. Written without
the author's rig: only tests.pilot.helpers constants are shared. No real env/key/auth/state/network."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import tempfile
import unicodedata
import unittest
from pathlib import Path

from reviewer.contracts.canonical import digest
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.pilot import positive as P
from reviewer.pilot.profile import RUN_CEILING_USD_MICROS
from reviewer.runtime import RuntimeLedger, Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.pilot.helpers import AUTH, FAKE_KEY, SONNET

REPO = P.REPO
CID, CREPO = "control-case-1", "owner/control-repo"
BASE = {"app/store.py": "def total(xs):\n    return sum(xs)\n", "app/util.py": "VALUE = 1\n"}
HEAD = {"app/store.py": "def total(xs):\n    return sum(xs) + 1\n", "app/util.py": "VALUE = 1\n"}
USAGE = {"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200, "cost": 0, "is_byok": True,
         "cost_details": {"upstream_inference_cost": 0.0042}, "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
         "completion_tokens_details": {"reasoning_tokens": 0}}
BASELINE = 70_576
EMPTY = {"contextRequests": [], "output": {"hypotheses": []}}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def tree(root: Path) -> dict:
    return {str(p.relative_to(root)): sha(p.read_bytes()) for p in sorted(root.rglob("*")) if p.is_file()}


def scope_hashes(repo: Path) -> dict:
    out = {}
    for scope in ("reviewer", "fixtures/retrieval-positive"):
        for p in sorted((repo / scope).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc":
                out[str(p.relative_to(repo))] = sha(p.read_bytes())
    return out


def force_remove(path: Path) -> None:
    for dp, dn, _ in os.walk(path):
        for d in [dp, *[os.path.join(dp, x) for x in dn]]:
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


class Fake:
    """Fake OpenRouter: answers from a script; records every request."""

    def __init__(self, script=None):
        # EXPLORE-FLOOR: the hop-0 empty answer is a draft under investigator.impact@v2; the second EMPTY answers the
        # one floor continuation.
        self.script = script or [EMPTY, EMPTY]
        self.requests = []

    def __call__(self, req):
        self.requests.append(req)
        d = {"id": f"gen-{len(self.requests)}", "model": SONNET, "provider": "Anthropic",
             "choices": [{"index": 0, "finish_reason": "stop",
                          "message": {"role": "assistant", "content": json.dumps(self.script[len(self.requests) - 1])}}],
             "usage": USAGE}
        return HttpResponse(200, {}, json.dumps(d).encode())


class Rig(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(lambda: (force_remove(Path(t.name)), self._quiet(t)))
        self.tmp = Path(os.path.realpath(t.name))
        self.op = self.tmp / "op"
        self.state = self.op / "state"
        self.state.mkdir(parents=True)
        self.ctl = self.tmp / "c" / "control"
        self.pins = self.op / "pins.json"
        self.baseline = self.op / "baseline.json"
        self.baseline.write_text(json.dumps({"schema": "software-baseline@1", "capturedAt": "2026-10-27T00:00:00Z",
                                             "files": scope_hashes(REPO)}))
        self.auth = self.op / "auth.json"
        self.write_auth(AUTH)
        self.env = self.op / "dot.env"
        self.env.write_text("openrouter_key=never-read\n")
        self.out = self.tmp / "out"
        self.loads = []
        self.src_before = scope_hashes(REPO)
        self.addCleanup(lambda: self.assertEqual(scope_hashes(REPO), self.src_before, "source or fixture changed"))
        self.build()

    @staticmethod
    def _quiet(t):
        try:
            t.cleanup()
        except FileNotFoundError:
            pass

    def write_auth(self, doc):
        self.auth.write_text(json.dumps(doc))
        os.chmod(self.auth, 0o600)

    def build(self, base=None, head=None):
        force_remove(self.ctl.parent)
        for side, files in (("base", base or BASE), ("head", head or HEAD)):
            for rel, text in files.items():
                (self.ctl / side / rel).parent.mkdir(parents=True, exist_ok=True)
                (self.ctl / side / rel).write_text(text)
        self.write_pins()

    def doc(self, **over):
        d = {"schema": "control-pins@1", "caseId": CID, "repo": CREPO, "base": tree(self.ctl / "base"),
             "head": tree(self.ctl / "head")}
        d.update(over)
        return d

    def write_pins(self, doc=None, raw=None):
        self.pins.write_text(raw if raw is not None else json.dumps(self.doc() if doc is None else doc))

    def seed(self, total=50_000_000, committed=BASELINE):
        auth = {**AUTH, "maxUsdMicrosTotal": total}
        self.write_auth(auth)
        h = trusted_authorization(self.auth)
        led = RuntimeLedger(self.state / P.LEDGER_NAME, 50_000_000)
        k = "prior|INVESTIGATE|investigator|generalist|0|0"
        led.admit(k, 100_000, model=SONNET)
        led.finish(k, outcome="processed", generationId="gen-prior", routerCostUsdMicros=0,
                   upstreamInferenceCostUsdMicros=committed, isByok=True, tokenPricedUsdMicros=committed,
                   costBasis="router-reported")
        b = SpendBook(h, self.state / P.BOOK_NAME)
        b.reserve("prior", 100_000)
        b.settle("prior", committed)

    def state_bytes(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir()}

    def loader(self, path, *, forbidden_roots=()):
        self.loads.append(str(path))
        return Secret(FAKE_KEY)

    def opts(self, **over):
        d = dict(mode="plan", source_baseline=str(self.baseline), out_dir=str(self.out), auth=str(self.auth),
                 control_dir=str(self.ctl), control_id=CID, control_repo=CREPO, control_pins=str(self.pins))
        d.update(over)
        return P.PositiveOptions(**d)

    def live_opts(self, **over):
        d = dict(mode="live", state_dir=str(self.state), env_file=str(self.env), baseline_micros=BASELINE, confirm_live=True)
        d.update(over)
        return self.opts(**d)

    def snapshot_dirs(self):
        """Every file under the operator dir and tmp (not the control): detects stray writes."""
        return sorted(str(p.relative_to(self.tmp)) for p in self.tmp.rglob("*") if self.ctl not in p.parents and p != self.ctl)

    def refused(self, opts, exc=(P.PositiveError,), fake=None):
        """The whole refusal contract: typed refusal, no request, key loader untouched, state/out/stray files unchanged."""
        fake = fake or Fake()
        before_state, before_files = self.state_bytes(), self.snapshot_dirs()
        with self.assertRaises(exc) as c:
            P.run_positive(opts, transport=fake, key_loader=self.loader)
        self.assertEqual(fake.requests, [])
        self.assertEqual(self.loads, [])
        self.assertEqual(self.state_bytes(), before_state)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.snapshot_dirs(), before_files)
        return str(c.exception)


# =========================================================== A. adverse control content / pins (live mode, state seeded)

class TreeAndPinRefusals(Rig):
    def setUp(self):
        super().setUp()
        self.seed()

    def go(self, **over):
        return self.refused(self.live_opts(**over))

    def test_changed_extra_missing_unpinned_dot_dir(self):
        cases = {
            "changed base": lambda: (self.ctl / "base/app/util.py").write_text("VALUE = 2\n"),
            "changed head": lambda: (self.ctl / "head/app/store.py").write_bytes(b"x"),
            "extra head": lambda: (self.ctl / "head/app/new.py").write_text("x = 1\n"),
            "missing base": lambda: (self.ctl / "base/app/util.py").unlink(),
            "dot dir": lambda: ((self.ctl / "head/.git").mkdir(), (self.ctl / "head/.git/config").write_text("x")),
            "top-level extra": lambda: (self.ctl / "notes.txt").write_text("hint"),
            "top-level missing": lambda: shutil.rmtree(self.ctl / "head"),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                self.build()
                mutate()
                self.go()

    def test_links_special_files_executable_and_hardlink_escape(self):
        def symfile():
            (self.ctl / "head/app/link.py").symlink_to(self.ctl / "head/app/util.py")

        def symdir():
            (self.ctl / "head/lnk").symlink_to(self.ctl / "head/app")

        def fifo():
            os.mkfifo(self.ctl / "head/app/pipe")

        def exe():
            os.chmod(self.ctl / "head/app/util.py", 0o755)
            self.write_pins()

        def side_link():
            shutil.rmtree(self.ctl / "head")
            (self.ctl / "head").symlink_to(self.ctl / "base")

        for name, mutate in {"symlink file": symfile, "symlink dir": symdir, "fifo": fifo, "executable": exe,
                             "head is a link to base": side_link}.items():
            with self.subTest(name):
                self.build()
                mutate()
                self.go()

    def test_control_dir_final_component_link_and_checkout_overlap(self):
        link = self.tmp / "ctl-link"
        link.symlink_to(self.ctl)
        self.go(control_dir=str(link))
        up = self.tmp / "up"
        up.symlink_to(REPO)                                   # a symlinked PARENT that resolves into the checkout
        self.go(control_dir=str(up / "fixtures" / "retrieval-positive"))
        self.go(control_dir=str(REPO / "no-such-control"))
        self.go(control_pins=str(up / "pins.json"))
        self.go(control_pins=str(REPO / "pins.json"))

    def test_pins_documents(self):
        good = self.doc()
        bad = {
            "dup key": json.dumps(good)[:-1] + ', "caseId": "x"}',
            "dup nested": '{"schema": "control-pins@1", "caseId": "%s", "repo": "%s", "base": {"a": "%s", "a": "%s"}, "head": {}}'
                          % (CID, CREPO, "0" * 64, "1" * 64),
            "extra key": json.dumps({**good, "note": "x"}),
            "missing key": json.dumps({k: v for k, v in good.items() if k != "repo"}),
            "schema": json.dumps({**good, "schema": "control-pins@2"}),
            "other id": json.dumps({**good, "caseId": "control-case-2"}),
            "other repo": json.dumps({**good, "repo": "owner/other"}),
            "uppercase digest": json.dumps({**good, "base": {k: v.upper() for k, v in good["base"].items()}}),
            "short digest": json.dumps({**good, "base": {k: v[:-1] for k, v in good["base"].items()}}),
            "sha256 prefix": json.dumps({**good, "base": {k: "sha256:" + v for k, v in good["base"].items()}}),
            "empty base": json.dumps({**good, "base": {}}),
            "dotdot path": json.dumps({**good, "base": {**good["base"], "../x": "0" * 64}}),
            "absolute path": json.dumps({**good, "head": {**good["head"], "/etc/passwd": "0" * 64}}),
            "backslash path": json.dumps({**good, "head": {**good["head"], "a\\b": "0" * 64}}),
            "list top": "[]", "not json": "{", "empty": "", "nan": json.dumps(good).replace('"base"', '"x": NaN, "base"'),
            "oversize": " " * ((4 << 20) + 1) + json.dumps(good),
        }
        for name, raw in bad.items():
            with self.subTest(name):
                self.write_pins(raw=raw)
                self.go()

    def test_pins_file_must_be_a_regular_nonlink_file(self):
        real = self.op / "real-pins.json"
        real.write_text(json.dumps(self.doc()))
        self.pins.unlink()
        self.pins.symlink_to(real)
        self.go()
        self.pins.unlink()
        self.go()                                             # absent

    def test_pins_directory_fails_closed(self):
        self.pins.unlink()
        self.pins.mkdir()
        self.refused(self.live_opts(), exc=(Exception,))

    def test_D1_pins_directory_is_a_typed_refusal(self):
        """Was defect D1 (IsADirectoryError / traceback). Typed refusal, no wire/key/state/output effect, descriptor not leaked."""
        self.pins.unlink()
        self.pins.mkdir()
        self.assertIn("not a regular file", self.go())
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(20):
            with self.assertRaises(P.PositiveError):
                P._read_pins(self.opts())
        self.assertEqual(len(os.listdir("/proc/self/fd")), before, "file descriptor leaked on the refusal path")

    @unittest.expectedFailure
    def test_DEFECT_D4_pins_fifo_must_not_hang_the_host(self):
        """Open limit D4 (author-declared, outside HOST-03): a FIFO as the pins file blocks os.open forever (no O_NONBLOCK).
        Bounded probe in a thread; the FIFO is released afterwards."""
        import threading
        self.pins.unlink()
        os.mkfifo(self.pins)
        res = []
        t = threading.Thread(target=lambda: res.append(self._probe()), daemon=True)
        t.start()
        t.join(2)
        hung = t.is_alive()
        if hung:                                              # release the blocked open so the thread ends
            fd = os.open(self.pins, os.O_WRONLY)
            os.close(fd)
            t.join(5)
        self.assertFalse(hung, "opening a FIFO pins file blocked the host")

    def _probe(self):
        try:
            P._read_pins(self.opts())
        except Exception as e:  # noqa: BLE001
            return e

    def test_file_size_cap_and_unsafe_names(self):
        big = self.ctl / "head/app/big.bin"
        big.write_bytes(b"\0" * ((8 << 20) + 1))
        self.write_pins()
        self.go()
        big.unlink()
        evil = self.ctl / "head/app" / "a\x1b[31mred"
        evil.write_text("x")
        self.go()                                             # unsafe name: refused, fail closed

    def test_D2_untrusted_names_never_reach_the_operator_as_raw_controls(self):
        """Was defect D2. Every refusal branch that names an untrusted entry must print ASCII-escaped, printable text only."""
        names = ["a\x1b[31mred", "bel\x07", "bidi\u202eexe", "nul\x00x", "nl\nx", "uni\u00e9", "c1\x9bcsi", "tab\tx"]
        for i, n in enumerate(names):
            for kind in ("file", "symlink", "fifo", "dirfile", "unpinned-dot"):
                with self.subTest(name=n, kind=kind):
                    self.build()
                    d = self.ctl / "head/app"
                    try:
                        if kind == "file":
                            (d / n).write_text("x")
                        elif kind == "symlink":
                            (d / n).symlink_to("util.py")
                        elif kind == "fifo":
                            os.mkfifo(d / n)
                        elif kind == "dirfile":
                            (d / n).mkdir()
                            (d / n / "f").write_text("x")
                        else:
                            (self.ctl / "head" / ("." + n)).write_text("x")
                    except (OSError, ValueError):
                        continue                              # this filesystem cannot hold that name
                    msg = self.go()
                    self.assertTrue(msg.isprintable() and not any(unicodedata.category(c) in ('Cf', 'Cc', 'Zl', 'Zp') for c in msg), ascii(msg))
        # the escaped form is still informative
        self.build()
        (self.ctl / "head/app/a\x1b[31mred").write_text("x")
        self.assertIn("\\x1b", self.go())
        # and through the CLI: stderr stays free of raw controls
        o, e = io.StringIO(), io.StringIO()
        code = P.main(["--mode", "plan", "--source-baseline", str(self.baseline), "--out", str(self.out), "--auth", str(self.auth),
                       "--control-dir", str(self.ctl), "--control-id", CID, "--control-repo", CREPO, "--control-pins", str(self.pins)],
                      out=o, err=e, key_loader=self.loader)
        code, out, err = code, o.getvalue(), e.getvalue()
        self.assertEqual((code, out), (2, ""))
        self.assertTrue(all(c == "\n" or 32 <= ord(c) < 127 for c in err), ascii(err))
        self.assertNotIn("Traceback", err)

    def test_identical_trees_and_empty_side(self):
        self.build(head=BASE)
        self.go()

    def test_identity_options(self):
        # the pins agree with the options, so only the host's own identity rules can refuse these
        self.write_pins(self.doc(caseId=P.CASE_ID))
        self.go(control_id=P.CASE_ID)
        self.write_pins(self.doc(repo=P.CASE_REPO))
        self.go(control_repo=P.CASE_REPO)
        self.write_pins()
        for name, over in {"uppercase id": dict(control_id="Control-Case"), "empty id": dict(control_id=""),
                           "slash id": dict(control_id="a/b"), "long id": dict(control_id="a" * 65),
                           "bad repo": dict(control_repo="noslash"), "upper repo": dict(control_repo="Owner/Repo"),
                           "partial: no dir": dict(control_dir=None), "partial: no id": dict(control_id=None),
                           "partial: no repo": dict(control_repo=None), "partial: no pins": dict(control_pins=None)}.items():
            with self.subTest(name):
                self.go(**over)

    def test_trust_domain_overlaps(self):
        inside = self.ctl / "head"
        d = {"state in control": dict(state_dir=str(inside)), "env in control": dict(env_file=str(inside / "app/util.py")),
             "auth in control": dict(auth=str(inside / "app/util.py")), "out in control": dict(out_dir=str(inside / "out")),
             "baseline in control": dict(source_baseline=str(inside / "app/util.py")),
             "control in state": dict(state_dir=str(self.ctl.parent)), "out is control parent": dict(out_dir=str(self.ctl.parent)),
             "out contains control": dict(out_dir=str(self.tmp)), "pins is baseline": dict(control_pins=str(self.baseline)),
             "out = pins": dict(out_dir=str(self.pins)), "out inside pins dir tree": dict(out_dir=str(self.pins / "x"))}
        for name, over in d.items():
            with self.subTest(name):
                self.go(**over)

    def test_config_inside_control_refused_before_anything(self):
        cfg = self.ctl / "head" / "pullo.toml"
        cfg.write_text('schema = "pullo-config@1"\n')
        self.write_pins()
        self.refused(self.live_opts(config=str(cfg)), exc=(Exception,))

    def test_state_and_auth_not_widened_or_mismatched(self):
        # authorization total larger than the existing book/ledger: refused before key/network (original $50 state only)
        self.write_auth({**AUTH, "maxUsdMicrosTotal": 60_000_000})
        self.refused(self.live_opts(), exc=(Exception,))
        # missing state dir / wrong baseline
        self.seed()
        self.refused(self.live_opts(baseline_micros=BASELINE + 1), exc=(Exception,))
        self.refused(self.live_opts(state_dir=str(self.tmp / "nope")), exc=(Exception,))


class CheckoutAndLayers(Rig):
    """Each trust-boundary layer exercised on its own (defence in depth), plus a control that REALLY sits in the checkout."""

    def fake_checkout(self):
        fake = self.tmp / "fakerepo"
        fake.mkdir()
        old = P.REPO
        P.REPO = fake
        self.addCleanup(setattr, P, "REPO", old)
        return fake

    def test_real_control_dir_inside_the_checkout_is_refused(self):
        fake = self.fake_checkout()
        shutil.copytree(self.ctl, fake / "ctl")
        self.ctl = fake / "ctl"
        self.write_pins()
        self.refused(self.opts())

    def test_real_pins_file_inside_the_checkout_is_refused(self):
        fake = self.fake_checkout()
        self.pins = fake / "pins.json"
        self.write_pins()
        self.refused(self.opts())

    def test_real_control_that_contains_the_checkout_is_refused(self):
        fake = self.tmp / "c" / "control" / "base" / "fakerepo"
        self.assertTrue(self.ctl in fake.parents)
        old = P.REPO
        P.REPO = fake
        self.addCleanup(setattr, P, "REPO", old)
        self.refused(self.opts())

    def prepared(self):
        return P.prepare(self.opts())

    def test_layer_config_refuses_a_config_inside_the_control(self):
        cfg = self.ctl / "pullo.toml"
        cfg.write_text('schema = "pullo-config@1"\n')
        with self.assertRaises(Exception) as c:
            P.effective_config(self.opts(config=str(cfg)))
        self.assertEqual(type(c.exception).__name__, "ConfigError")

    def test_layer_output_refuses_inside_the_control_and_the_pins_dir_file(self):
        for out in (self.ctl / "out", self.pins / "x"):
            with self.assertRaises(P.PositiveError):
                P.check_out(self.opts(out_dir=str(out)))

    def test_layer_plan_authorization_refuses_an_auth_file_inside_the_control(self):
        prep = self.prepared()
        a = self.ctl / "auth.json"
        a.write_text(self.auth.read_text())
        os.chmod(a, 0o600)
        with self.assertRaises(Exception) as c:
            P.plan_mode(self.opts(auth=str(a)), prep, cfg=P.effective_config(self.opts()))
        self.assertEqual(type(c.exception).__name__, "AuthorizationError")
        self.assertEqual(self.loads, [])

    def test_layer_live_authorization_and_key_loader_refuse_files_inside_the_control(self):
        self.seed()
        prep = self.prepared()
        cfg = P.effective_config(self.opts())
        a = self.ctl / "auth.json"
        a.write_text(self.auth.read_text())
        os.chmod(a, 0o600)
        fake, before = Fake(), self.state_bytes()
        with self.assertRaises(Exception) as c:
            P.live_mode(self.live_opts(auth=str(a)), prep, transport=fake, key_loader=self.loader, cfg=cfg)
        self.assertEqual(type(c.exception).__name__, "AuthorizationError")
        # the REAL key loader, an env file inside the control, everything else valid
        e = self.ctl / "key.env"
        e.write_text("openrouter_key=" + FAKE_KEY + "\n")
        os.chmod(e, 0o600)
        from reviewer.runtime import load_openrouter_key
        with self.assertRaises(Exception) as c:
            P.live_mode(self.live_opts(env_file=str(e)), prep, transport=fake, key_loader=load_openrouter_key, cfg=cfg)
        self.assertEqual(type(c.exception).__name__, "EnvFileError")
        self.assertEqual((fake.requests, self.state_bytes(), self.out.exists()), ([], before, False))

    def test_layer_pipeline_refuses_run_output_inside_the_control(self):
        prep = self.prepared()
        profile, plan, policy = P._profile_parts()
        spec = P.build_spec(self.opts(), prep, P.DisabledProvider and None, self.ctl / "runs", profile, plan, policy)
        self.assertIn(self.ctl.resolve(), [Path(os.path.realpath(r)) for r in spec.host.forbidden_roots])


# =========================================================== B. positive composition

class Composition(Rig):
    def plan(self, **over):
        return P.run_positive(self.opts(**over), key_loader=self.loader)

    def live(self, fake=None, seeded=False, **over):
        if not seeded:
            self.seed()
        fake = fake or Fake()
        return P.run_positive(self.live_opts(**over), transport=fake, key_loader=self.loader), fake

    def test_plan_touches_nothing_and_wire_equals_live_first_request(self):
        self.seed()
        before, files = self.state_bytes(), self.snapshot_dirs()
        rep = self.plan()
        self.assertEqual((rep["status"], rep["ok"], rep["synthetic"], rep["case"], rep["repo"]), ("planned", True, True, CID, CREPO))
        self.assertEqual((self.loads, self.state_bytes(), self.snapshot_dirs()), ([], before, files))
        p = rep["plan"]
        self.assertEqual((p["retries"], p["repairs"], p["providerCalls"], p["networkCalls"], p["keyRead"]), (0, 0, 0, 0, False))
        self.assertLessEqual(p["worstCaseAdmissionUsdMicros"], RUN_CEILING_USD_MICROS)
        self.assertEqual(p["runCeilingUsdMicros"], 4_000_000)
        self.assertEqual(p["firstRequest"]["model"], SONNET)
        live, fake = self.live(seeded=True)
        self.assertEqual(live["status"], "completed")
        self.assertEqual(sha(fake.requests[0].body), p["firstRequest"]["bodySha256"])
        self.assertEqual(live["control"], rep["control"])

    def test_four_dollar_run_ceiling_holds_with_a_wider_authorization(self):
        # an operator authorization with a larger per-run cap must not widen the host profile's $4 ceiling
        self.write_auth({**AUTH, "maxUsdMicrosPerRun": 20_000_000})
        rep = self.plan()
        self.assertEqual(rep["plan"]["runCeilingUsdMicros"], 4_000_000)
        self.assertLessEqual(rep["plan"]["worstCaseAdmissionUsdMicros"], 4_000_000)

    def test_nothing_secret_or_trust_domain_in_wire_report_or_trace(self):
        rep, fake = self.live()
        wire = b"".join(r.body for r in fake.requests).decode().lower()
        for n in (str(self.ctl), str(self.pins), P.CONTROL_LABEL, rep["control"]["pinsDigest"], "control-pins", "gold", "ground",
                  FAKE_KEY, str(self.op), str(self.tmp)):
            self.assertNotIn(n.lower(), wire, n)
        user = json.loads(fake.requests[0].body)["messages"][1]["content"]
        self.assertEqual(json.loads(user)["untrustedPullRequest"], {"title": "", "body": ""})
        saved = "".join(p.read_text(errors="replace") for p in self.out.rglob("*") if p.is_file())
        for n in (FAKE_KEY, "never-read"):
            self.assertNotIn(n, saved + json.dumps(rep))
        self.assertEqual(self.loads, [str(self.env)])          # exactly one key load, of the selected env file

    def test_case_input_is_exactly_the_generic_synthetic_shape(self):
        c = P.prepare(self.opts()).case
        self.assertEqual(set(c), {"schema", "id", "repo", "synthetic", "base", "head", "pr"})
        self.assertEqual((c["synthetic"], c["pr"], c["id"], c["repo"]), (True, {"title": "", "body": ""}, CID, CREPO))

    def test_strict_replay_zero_key_network_spend_and_pin_checks(self):
        rep, _ = self.live()
        before = self.state_bytes()
        d = dict(mode="replay", auth=None, out_dir=str(self.tmp / "r1"), replay_trace=rep["paths"]["trace"],
                 trace_digest=rep["traceDigest"]["value"])
        self.loads.clear()
        rr = P.run_positive(self.opts(**d), transport=None, key_loader=self.loader)
        self.assertEqual((rr["status"], rr["ok"], rr["providerCalls"]), ("completed", True, 0))
        self.assertEqual((rr["replay"]["liveCalls"], rr["replay"]["newSpendUsdMicros"], rr["replay"]["keyRead"],
                          rr["replay"]["networkCalls"]), (0, 0, False, 0))
        self.assertEqual((self.loads, self.state_bytes()), ([], before))
        # same files, different declared id -> different identity -> the trace must not replay
        self.write_pins(self.doc(caseId="control-case-9"))
        d["out_dir"] = str(self.tmp / "r2")
        with self.assertRaises(Exception) as c:
            P.run_positive(self.opts(control_id="control-case-9", **d), key_loader=self.loader)
        self.assertEqual(type(c.exception).__name__, "PipelineError")
        self.assertFalse((self.tmp / "r2").exists() and any((self.tmp / "r2").rglob("*.json")))
        # wrong digest pin
        self.write_pins()
        d.update(out_dir=str(self.tmp / "r3"), trace_digest="sha256:" + "0" * 64)
        with self.assertRaises(Exception):
            P.run_positive(self.opts(**d), key_loader=self.loader)
        self.assertEqual((self.loads, self.state_bytes()), ([], before))

    def test_replay_refuses_a_changed_control_before_any_replay(self):
        rep, _ = self.live()
        (self.ctl / "head/app/util.py").write_text("VALUE = 3\n")           # pins no longer match
        d = dict(mode="replay", auth=None, out_dir=str(self.tmp / "r"), replay_trace=rep["paths"]["trace"],
                 trace_digest=rep["traceDigest"]["value"])
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.opts(**d), key_loader=self.loader)
        self.assertFalse((self.tmp / "r").exists())

    def test_replay_trace_inside_control_refused(self):
        rep, _ = self.live()
        t = self.ctl / "head" / "trace.jsonl"
        shutil.copy(rep["paths"]["trace"], t)
        self.write_pins()
        d = dict(mode="replay", auth=None, out_dir=str(self.tmp / "r"), replay_trace=str(t),
                 trace_digest=rep["traceDigest"]["value"])
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.opts(**d), key_loader=self.loader)

    def test_toctou_between_pin_check_and_snapshot(self):
        real, f = P.build_manifest, self.ctl / "head/app/util.py"

        def racing(path, *a, **k):
            if str(path).endswith("head"):
                f.write_text("VALUE = 99\n")
            return real(path, *a, **k)

        P.build_manifest = racing
        try:
            self.seed()
            with self.assertRaises(P.PositiveError) as c:
                P.run_positive(self.live_opts(), transport=Fake(), key_loader=self.loader)
        finally:
            P.build_manifest = real
        self.assertIn("changed while", str(c.exception))
        self.assertEqual(self.loads, [])

    def test_change_after_prepare_is_not_silently_reviewed(self):
        """The pipeline must notice a pinned file edited after the pin check (no silent read of different content)."""
        self.seed()
        fake = Fake()
        real_run, f = P.run_review, self.ctl / "head/app/store.py"

        def late(spec):
            f.write_text("def total(xs):\n    return -1\n")
            return real_run(spec)

        try:
            rep = P.run_positive(self.live_opts(), transport=fake, key_loader=self.loader, runner=late)
            noticed = (not rep["ok"]) or rep["status"] != "completed"
            self.assertTrue(noticed or b"return -1" not in b"".join(r.body for r in fake.requests),
                            "edited content reached the model although it differs from the pinned/identified snapshot")
        except Exception as e:  # noqa: BLE001 - any typed refusal is acceptable here
            self.assertNotIn("Traceback", str(e))


# =========================================================== C. identity isolation

class Identity(Rig):
    def ident(self, **over):
        o = self.opts(**over)
        prep = P.prepare(o)
        cfg = P.config_identity(prep, *P._profile_parts())
        evr = P.eval_run_id(o, cfg)
        return evr, P.provider_scope(evr, prep), digest(cfg)

    def test_distinct_controls_never_share_run_ids_and_same_control_is_stable(self):
        a = self.ident()
        self.assertEqual(a, self.ident())
        seen = {a[0]: "base"}
        variants = {}
        self.write_pins(self.doc(caseId="control-case-2"))
        variants["id"] = self.ident(control_id="control-case-2")
        self.write_pins(self.doc(repo="owner/other"))
        variants["repo"] = self.ident(control_repo="owner/other")
        self.write_pins()
        (self.ctl / "head/app/util.py").write_text("VALUE = 5\n")
        self.write_pins()
        variants["file"] = self.ident()
        for k, v in variants.items():
            self.assertNotIn(v[0], seen, k)
            self.assertNotEqual(v[1], a[1], k)
            seen[v[0]] = k
        self.build()
        self.assertEqual(self.ident(), a)
        (self.ctl / "head/app/zz.py").write_text("")
        self.write_pins()
        self.assertNotIn(self.ident()[0], seen)

    def test_default_identity_has_exactly_the_original_keys_and_no_control(self):
        o = self.opts(control_dir=None, control_id=None, control_repo=None, control_pins=None)
        prep = P.prepare(o)
        cfg = P.config_identity(prep, *P._profile_parts())
        self.assertEqual(set(cfg), {"schema", "caseId", "sourceScopeDigest", "snapshotIds", "profile", "plan", "retrievalPolicy",
                                    "prTextSupplied"})
        self.assertEqual((cfg["caseId"], prep.case["repo"], prep.fixture), (P.CASE_ID, P.CASE_REPO, P.FIXTURE))
        rep = P.run_positive(o, key_loader=self.loader)
        self.assertNotIn("control", rep)
        self.assertEqual((rep["case"], rep["repo"]), (P.CASE_ID, P.CASE_REPO))

    def test_snapshot_ids_bind_content(self):
        a = P.prepare(self.opts()).case
        (self.ctl / "base/app/util.py").write_text("VALUE = 8\n")
        self.write_pins()
        b = P.prepare(self.opts()).case
        self.assertNotEqual(a["base"]["snapshotId"], b["base"]["snapshotId"])
        self.assertEqual(a["head"]["snapshotId"], b["head"]["snapshotId"])


# =========================================================== D. default path vs the pristine main module (differential)

class DefaultDifferential(Rig):
    MAIN = os.environ.get("CONTROL_REVIEW_MAIN_POSITIVE")

    @unittest.skipUnless(os.environ.get("CONTROL_REVIEW_MAIN_POSITIVE"), "set to the pristine main positive.py")
    def test_default_plan_is_identical_to_main(self):
        spec = importlib.util.spec_from_file_location("reviewer.pilot._main_positive", self.MAIN)
        m = importlib.util.module_from_spec(spec)
        import sys
        sys.modules[spec.name] = m
        spec.loader.exec_module(m)
        kw = dict(source_baseline=str(self.baseline), out_dir=str(self.out), auth=str(self.auth))
        a = P.run_positive(P.PositiveOptions(mode="plan", **kw), key_loader=self.loader)
        b = m.run_positive(m.PositiveOptions(mode="plan", **kw), key_loader=self.loader)
        for k in ("status", "ok", "case", "repo", "synthetic", "snapshotIds", "sourceBaseline", "plan", "reviewModels", "quality",
                  "prText", "outcome"):
            self.assertEqual(a.get(k), b.get(k), k)
        self.assertEqual(set(a), set(b))
        self.assertEqual(P.FIXTURE, m.FIXTURE)
        self.assertEqual((P.CASE_ID, P.CASE_REPO, P.SCOPES), (m.CASE_ID, m.CASE_REPO, m.SCOPES))


# =========================================================== E. CLI

class Cli(Rig):
    def main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        return P.main(argv, out=out, err=err, key_loader=self.loader), out.getvalue(), err.getvalue()

    def argv(self, *more):
        return ["--mode", "plan", "--source-baseline", str(self.baseline), "--out", str(self.out), "--auth", str(self.auth), *more]

    def full(self):
        return ["--control-dir", str(self.ctl), "--control-id", CID, "--control-repo", CREPO, "--control-pins", str(self.pins)]

    def test_plan_json_and_partial_flags(self):
        code, out, err = self.main(self.argv(*self.full(), "--json"))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["case"], CID)
        for i in range(0, 8, 2):
            f = self.full()
            del f[i:i + 2]
            code, out, err = self.main(self.argv(*f))
            self.assertEqual(code, 2, f)
            self.assertTrue(err.startswith("error: PositiveError"), err)
        self.assertFalse(self.out.exists())

    def test_every_refusal_is_a_clean_exit_2_without_file_content(self):
        (self.ctl / "head/app/util.py").write_text("SECRET_TOKEN_IN_FILE = 1\n")      # now unpinned-changed
        code, out, err = self.main(self.argv(*self.full()))
        self.assertEqual((code, out), (2, ""))
        self.assertNotIn("SECRET_TOKEN_IN_FILE", err)
        # ids the contract might reject but the slug regex accepts must still exit cleanly
        for bad in ("a.b", "a_b", "a--b", "0", "a" * 64):
            self.build()
            self.write_pins(self.doc(caseId=bad))
            code, out, err = self.main(self.argv("--control-dir", str(self.ctl), "--control-id", bad, "--control-repo", CREPO,
                                                 "--control-pins", str(self.pins)))
            self.assertIn(code, (0, 2), (bad, err))
            self.assertNotIn("Traceback", err)
        for bad in ("a/b", "0/0", "a-b/c_d"):
            self.write_pins(self.doc(repo=bad))
            self.out = self.tmp / ("o" + bad.replace("/", "_"))
            code, out, err = self.main(["--mode", "plan", "--source-baseline", str(self.baseline), "--out", str(self.out),
                                        "--auth", str(self.auth), "--control-dir", str(self.ctl), "--control-id", CID,
                                        "--control-repo", bad, "--control-pins", str(self.pins)])
            self.assertIn(code, (0, 2), (bad, err))

    def test_dotted_owner_repo_fails_closed_before_state_key_output(self):
        self.seed_none = None
        self.write_pins(self.doc(repo="a.b/c.d"))
        o = self.opts(control_repo="a.b/c.d")
        with self.assertRaises(Exception):
            P.run_positive(o, key_loader=self.loader)
        self.assertEqual((self.loads, self.out.exists()), ([], False))

    def test_D3_repos_the_contract_rejects_exit_2_cleanly_and_the_rest_build(self):
        """Was defect D3 (ContractViolation escaped main). Every id/repo the host admits must also build a CaseInput."""
        bad = ["a.b/c.d", "a_b/c", "-/c", "a/..", "a/.", "a/", "/a", "a//b", "a b/c", "A/b", "a/B", "x" * 40 + "/n", "a/b/c", "a.b/c"]
        for r in bad:
            with self.subTest(repo=r):
                self.out = self.tmp / ("o-" + str(abs(hash(r))))
                self.write_pins(self.doc(repo=r))
                code, out, err = self.main(["--mode", "plan", "--source-baseline", str(self.baseline), "--out", str(self.out),
                                            "--auth", str(self.auth), "--control-dir", str(self.ctl), "--control-id", CID,
                                            f"--control-repo={r}", "--control-pins", str(self.pins)])
                self.assertEqual((code, out), (2, ""), r)
                self.assertTrue(err.startswith("error: PositiveError"), err)
                self.assertNotIn("Traceback", err)
                self.assertFalse(self.out.exists())
        good = ["a-b/c.d_e", "o/n", "0/1", "owner/control-repo", "x" * 39 + "/" + "y" * 100]
        for r in good:
            with self.subTest(good=r):
                self.write_pins(self.doc(repo=r))
                o = self.opts(control_repo=r)
                P.check_options(o)
                self.assertEqual(P.prepare(o).case["repo"], r)
        # ids: whatever the host admits must build too
        for cid in ("a.b", "a_b", "a--b", "0", "a" * 64, "a-", "a."):
            with self.subTest(id=cid):
                self.write_pins(self.doc(caseId=cid))
                o = self.opts(control_id=cid)
                P.check_options(o)
                self.assertEqual(P.prepare(o).case["id"], cid)


if __name__ == "__main__":
    unittest.main()
