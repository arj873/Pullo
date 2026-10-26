#!/usr/bin/env python3
"""Runnable offline recipe for the all-pairs reference-score CLI. Stdlib only; everything here is INVENTED.

It builds a tiny pretend benchmark source (two pull requests, invented gold and tool comments), pins it, writes
invented all-pairs judgments, then runs the real `reviewer.benchmark reference-score` entry point in this process and
checks the report against numbers derived by hand below. It then shows the refusal and incomplete/missing/error/hidden
controls. No network, provider, credential, model or Git call happens, and nothing is written outside --workdir.

    nice -n 19 python3 -B examples/benchmark_demo.py            # new temporary workdir
    nice -n 19 python3 -B examples/benchmark_demo.py --workdir /path/that/does/not/exist/yet

The numbers describe this toy only. They say nothing about review quality, and the "judge" block is made up.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from reviewer.benchmark import load_source  # noqa: E402
from reviewer.benchmark.__main__ import main as benchmark_cli  # noqa: E402

REVISION = "feedface" * 5          # 40 hex characters; an invented label, not a real source revision
URL_A, URL_B = "https://example.invalid/demo/pull/1", "https://example.invalid/demo/pull/2"
REPO_NAME = "demo-repo"
TOOLS = ("demo-a", "demo-b")       # normal run
HIDDEN_TOOL = "mra-demo"           # the reference hides tool ids with the prefix "mra-"; used for the hidden control
JUDGE = {"model": "invented-judge-do-not-compare", "extractionPrompt": "demo.extract@v0", "dedupPrompt": "demo.dedup@v0",
         "matchPrompt": "demo.match@v0", "schemaSha256": "sha256:" + "0" * 64, "runRef": "demo-run-1"}
STAMP = "2026-01-01T00:00:00Z"
SOURCE_FILES = {"benchmark_data.json": "offline/results/benchmark_data.json",
                "pr_labels.json": "offline/results/pr_labels.json"}

# (comment, severity, category) -- severity is exactly one of Critical/High/Medium/Low
GOLD = {URL_A: [("INVENTED the retry loop never increments its counter", "High", "bug"),
                ("INVENTED the cache key leaves out the tenant id", "Medium", "data"),
                ("INVENTED a misleading variable name", "Low", "style")],
        URL_B: [("INVENTED the timeout is read in seconds but compared as milliseconds", "High", "bug"),
                ("INVENTED the access token is written to the debug log", "Critical", "security")]}
# tool -> url -> comment bodies. demo-b says nothing at all (a review with zero comments is still a review).
BODIES = {"demo-a": {URL_A: ["INVENTED retry loop spins forever", "INVENTED rename tmp, tmp is unclear"],
                     URL_B: ["INVENTED timeout units differ", "INVENTED add docs"]},
          "demo-b": {URL_A: [], URL_B: []},
          HIDDEN_TOOL: {URL_A: ["INVENTED retry loop spins forever"], URL_B: ["INVENTED timeout units differ"]}}
# Candidates the (here hand-written) producer extracted: [(candidate text, index of the source comment)] per tool/url.
CANDIDATES = {"demo-a": {URL_A: [("The retry loop never increments its counter, so it can spin forever.", 0),
                                 ("The variable name tmp is misleading.", 1),
                                 ("tmp should be renamed to something descriptive.", 1)],
                         URL_B: [("The timeout is compared in the wrong unit.", 0), ("Consider adding documentation.", 1)]},
              "demo-b": {URL_A: [], URL_B: []},
              HIDDEN_TOOL: {URL_A: [("The retry loop never increments its counter.", 0)],
                            URL_B: [("The timeout is compared in the wrong unit.", 0)]}}
# Ordered duplicate groups: lists of 0-based indices into the candidate list. Here candidates 1 and 2 say the same thing.
GROUPS = {("demo-a", URL_A): [[1, 2]]}
# Matches the producer decided: (candidate index, gold index) -> confidence. Every OTHER pair is match=false, confidence 0.
MATCHES = {("demo-a", URL_A): {(0, 0): 0.9, (1, 2): 0.8, (2, 2): 0.8},
           ("demo-a", URL_B): {(0, 0): 0.95},
           (HIDDEN_TOOL, URL_A): {(0, 0): 0.9}, (HIDDEN_TOOL, URL_B): {(0, 0): 0.9}}

# Hand-derived expectations (see the arithmetic in reviewer/benchmark/README.md): profile -> (tp, fp, fn, prs).
EXPECTED = {"demo-a": {"strict": (2, 1, 2, 2), "core": (2, 1, 2, 2), "all": (3, 1, 2, 2)},
            "demo-b": {"strict": (0, 0, 4, 2), "core": (0, 0, 4, 2), "all": (0, 0, 5, 2)}}


# ---------------------------------------------------------------------------------------------- recipes (stdlib only)
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_id(data: bytes) -> str:
    """Git object id of a file's bytes: sha1 over b"blob <size>\\0" + bytes."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - an object id, not a security hash


def canonical_digest(obj) -> str:
    """`sha256:` + sha256 of canonical JSON (sorted keys, no spaces, non-ASCII kept, NaN refused)."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return "sha256:" + sha256_hex(data)


def write_json(path: Path, obj) -> bytes:
    data = (json.dumps(obj, indent=1, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(data)
    return data


def build_source(store: Path, ops: Path) -> dict:
    """Write the invented raw source and labels into `store`; the proposal and pins into `ops`. Returns the paths."""
    urls = sorted(GOLD, key=lambda u: sha256_hex(u.encode()))        # ascending sha256 of the URL is the declared rank
    data = {u: {"pr_title": "INVENTED", "original_url": None, "source_repo": REPO_NAME, "golden_source_file": "g.json",
                "az_comment": None,
                "golden_comments": [{"comment": c, "severity": s, "category": k} for c, s, k in GOLD[u]],
                "reviews": [{"tool": t, "repo_name": f"{t}__{REPO_NAME}", "pr_url": None,
                             "review_comments": [{"path": "src/a.py" if i else None, "line": i + 1 if i else None,
                                                  "body": b, "created_at": STAMP} for i, b in enumerate(BODIES[t][u])]}
                            for t in (*TOOLS, HIDDEN_TOOL)]} for u in GOLD}
    labels = {u: {"derived": {"num_golden_comments": len(GOLD[u])}} for u in GOLD}
    raw = {"benchmark_data.json": write_json(store / "benchmark_data.json", data),
           "pr_labels.json": write_json(store / "pr_labels.json", labels)}
    pins = {"schema": "benchmark-source-pins@1", "revision": REVISION,
            "files": [{"name": n, "sourcePath": SOURCE_FILES[n], "bytes": len(b), "gitBlobSha": git_blob_id(b),
                       "sha256": "sha256:" + sha256_hex(b)} for n, b in raw.items()]}
    item = lambda u: {"url": u, "urlSha256": sha256_hex(u.encode())}   # noqa: E731
    proposal = {"schema": "benchmark-partition-proposal@1", "sourceRevision": REVISION,
                "rankedUniverse": {REPO_NAME: [item(u) for u in urls]},
                "preImportDevCandidates": [{"repo": REPO_NAME, **item(urls[0])}],
                "preImportFrozenCandidates": [{"repo": REPO_NAME, **item(urls[1])}]}
    write_json(ops / "pins.json", pins)
    write_json(ops / "proposal.json", proposal)
    return {"pins": ops / "pins.json", "data": store / "benchmark_data.json", "labels": store / "pr_labels.json",
            "proposal": ops / "proposal.json"}


def build_judgments(paths: dict, tool: str, url: str) -> dict:
    """One `reference-judgments@1` document: candidates, ordered duplicate groups with their digest, ALL G*C pairs."""
    src = load_source(paths["pins"], paths["data"], paths["labels"], paths["proposal"], expect_revision=REVISION)
    case = src.cases[url]
    comment_ids = [c.id for c in case.review(tool).comments]       # ids come from the loader, never from comment text
    cands = [{"id": f"{tool}:{n}", "sourceCommentId": comment_ids[k], "text": t}
             for n, (t, k) in enumerate(CANDIDATES[tool][url], 1)]
    matches = MATCHES.get((tool, url), {})
    pairs = [{"golden": g.id, "candidate": c["id"], "match": (ci, gi) in matches, "confidence": matches.get((ci, gi), 0)}
             for gi, g in enumerate(case.golden) for ci, c in enumerate(cands)]
    return {"schema": "reference-judgments@1", "caseUrl": url, "tool": tool, "judge": dict(JUDGE),
            "extraction": {"candidates": cands},
            "duplicateGroups": {"candidateListSha256": canonical_digest([[c["id"], c["text"]] for c in cands]),
                                "groups": [list(g) for g in GROUPS.get((tool, url), [])]},
            "pairs": pairs}


# ---------------------------------------------------------------------------------------------- CLI plumbing
def cli(*argv) -> tuple[int, dict | None, dict | None]:
    """Run the real entry point in-process. Returns (exit code, parsed stdout report | None, parsed stderr refusal | None)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = benchmark_cli([str(a) for a in argv])
    parse = lambda s: json.loads(s) if s.strip().startswith("{") else None   # noqa: E731
    return rc, parse(out.getvalue()), parse(err.getvalue())


def score(paths: dict, judgments: Path, out: Path, tools, cases=None):
    args = ["reference-score", "--pins", paths["pins"], "--data", paths["data"], "--labels", paths["labels"],
            "--proposal", paths["proposal"], "--expect-revision", REVISION, "--judgments", judgments, "--out", out,
            "--tools", *tools]
    if cases:
        args += ["--cases", *cases]
    return cli(*args)


def check(cond: bool, what: str, log: list) -> None:
    log.append(("ok  " if cond else "FAIL") + " " + what)
    if not cond:
        raise AssertionError(what)


def run(workdir: Path, log: list | None = None) -> dict:
    """Run the whole recipe under `workdir` (must not exist yet or be empty). Raises AssertionError on any mismatch."""
    log = [] if log is None else log
    workdir = Path(workdir)
    for part in (workdir, *workdir.parents):
        if part.name == ".git":
            raise SystemExit("refusing a workdir inside a .git directory")
    resolved = workdir.resolve()
    if any(resolved == r or r in resolved.parents for r in (REPO / "reviewer", REPO / "fixtures", REPO / "tests")):
        raise SystemExit("the workdir must be outside reviewer/, fixtures/ and tests/ (the CLI refuses reports there)")
    if workdir.exists() and any(workdir.iterdir()):
        raise SystemExit(f"{workdir} is not empty")
    store, ops, outd = workdir / "store", workdir / "ops", workdir / "out"
    for d in (store, ops, outd):
        d.mkdir(parents=True)
    paths = build_source(store, ops)

    # 0. recipe self-check: the hand-written digest/blob recipes equal the package's own helpers
    from reviewer.benchmark import jsonio
    sample = {"b": [1, "é"], "a": None}
    check(canonical_digest(sample) == jsonio.digest(sample), "digest recipe equals reviewer.benchmark.jsonio.digest", log)
    check(git_blob_id(b"x\n") == jsonio.git_blob_sha(b"x\n"), "git blob recipe equals jsonio.git_blob_sha", log)

    # 1. strict pinning: verify the raw files against the pins, then inspect the roster
    rc, rep, _ = cli("verify-pins", "--pins", paths["pins"], "--data", paths["data"], "--labels", paths["labels"],
                     "--expect-revision", REVISION)
    check(rc == 0 and rep == {"status": "verified", "revision": REVISION}, "verify-pins verifies both files", log)
    rc, rep, _ = cli("inspect", "--pins", paths["pins"], "--data", paths["data"], "--labels", paths["labels"],
                     "--proposal", paths["proposal"], "--expect-revision", REVISION)
    check(rc == 0 and rep["cases"] == 2 and rep["goldenTotal"] == 5 and not rep["goldenCountDisagreements"],
          "inspect: 2 cases, 5 gold, label counts agree", log)

    # 2. normal run: every (case, tool) document with all G*C pairs
    docs = [build_judgments(paths, t, u) for t in TOOLS for u in GOLD]
    check([len(d["pairs"]) for d in docs] == [3 * 3, 2 * 2, 0, 0], "all G*C pairs written (9, 4, 0, 0)", log)
    jp = ops / "judgments.json"
    write_json(jp, docs)
    rc, rep, _ = score(paths, jp, outd / "report.json", TOOLS)
    check(rc == 0 and rep["schema"] == "reference-score-report@1" and rep["complete"], "reference-score exits 0, complete", log)
    check(rep["sourceBound"] and rep["judgeStatus"] == "producer-declared, unverified", "source bound; judge unverified", log)
    for tool, want in EXPECTED.items():
        pooled = rep["tools"][tool]["pooled"]
        for prof, (tp, fp, fn, prs) in want.items():
            got = pooled[prof]["counts"]
            check((got["tp"], got["fp"], got["fn"], got["prs"]) == (tp, fp, fn, prs), f"{tool} {prof} counts {want[prof]}", log)
    core = rep["tools"]["demo-a"]["pooled"]["core"]
    check(abs(core["precision"] - 2 / 3) < 1e-12 and core["recall"] == 0.5 and abs(core["f1"] - 4 / 7) < 1e-12,
          "demo-a core precision 2/3, recall 1/2, F1 4/7", log)
    zero = rep["tools"]["demo-b"]["pooled"]["core"]
    check(zero["undefined"] == ["precision"] and zero["precision"] == 0.0 and zero["zeroConvention"] ==
          "reference-undefined-is-0", "demo-b precision undefined -> named zero, listed in `undefined`", log)
    a_a = rep["tools"]["demo-a"]["cases"]
    first = next(c for c in a_a if c["goldenCount"] == 3)
    check(first["duplicateGroups"] == 1 and first["evaluation"]["fp"] == 0 and first["evaluation"]["provenance"]["siblingMarked"],
          "ordered duplicate group protects its sibling (no false positive)", log)
    check("INVENTED" not in json.dumps(rep), "report carries ids and counts, no gold or comment text", log)
    check((outd / "report.json").is_file(), "report written to --out (O_EXCL, mode 0600)", log)

    controls = {}

    # 3. incomplete / missing / error / hidden: the run still exits 0 but the tool has NO headline pooled numbers
    def variant(name, mutate, tools, expect):
        ds = mutate([json.loads(json.dumps(d)) for d in docs if d["tool"] in tools])   # only the requested tools
        p = ops / f"{name}.json"
        write_json(p, ds)
        rc, rep, _ = score(paths, p, outd / f"{name}.json", tools)
        ok = rc == 0 and expect(rep)
        controls[name] = {"exit": rc}
        check(ok, f"{name}: exit 0, tool not complete, pooled is null", log)

    def drop_pair(ds):
        ds[0]["pairs"].pop()
        return ds

    def drop_doc(ds):
        del ds[1]                                                 # no document at all for demo-a on the second case
        return ds

    def pair_error(ds):
        ds[0]["pairs"][0] = {"golden": ds[0]["pairs"][0]["golden"], "candidate": ds[0]["pairs"][0]["candidate"],
                             "error": "judge call failed (invented)"}
        return ds

    entry_of = lambda r, t="demo-a": r["tools"][t]   # noqa: E731
    variant("incomplete", drop_pair, ["demo-a"], lambda r: not entry_of(r)["complete"] and entry_of(r)["pooled"] is None
            and len(entry_of(r)["incomplete"]) == 1 and entry_of(r)["partialPooled"]["notAScore"])
    variant("missing", drop_doc, ["demo-a"], lambda r: not entry_of(r)["complete"] and entry_of(r)["pooled"] is None
            and len(entry_of(r)["missing"]) == 1)
    variant("pair-error", pair_error, ["demo-a"], lambda r: not entry_of(r)["complete"] and entry_of(r)["pooled"] is None
            and len(entry_of(r)["pairErrorCases"]) == 1
            and next(c for c in entry_of(r)["cases"] if c["caseUrl"] == URL_A)["evaluation"]["errors"][0]["status"]
            == "judge-error")
    hidden_docs = [build_judgments(paths, HIDDEN_TOOL, u) for u in GOLD]
    p = ops / "hidden.json"
    write_json(p, hidden_docs)
    rc, rep, _ = score(paths, p, outd / "hidden.json", [HIDDEN_TOOL])
    check(rc == 0 and entry_of(rep, HIDDEN_TOOL)["referenceHidden"] and entry_of(rep, HIDDEN_TOOL)["pooled"] is None
          and not rep["complete"], "hidden: a reference-hidden tool id is never given pooled numbers", log)

    # 4. refusals: nothing is scored; exit 1 (bad content) or 2 (bad location/arguments)
    def refuses(name, code, want_exit, argv):
        rc, rep, err = cli(*argv)
        controls[name] = {"exit": rc, "code": err and err["code"]}
        check(rc == want_exit and rep is None and err is not None and err["code"] == code,
              f"refusal {name}: exit {want_exit}, code {code!r}", log)

    base = ["reference-score", "--pins", paths["pins"], "--data", paths["data"], "--labels", paths["labels"],
            "--proposal", paths["proposal"], "--judgments", jp, "--tools", *TOOLS]
    refuses("report-inside-store", "boundary", 2, [*base, "--out", store / "report.json"])
    refuses("report-inside-reviewer-root", "boundary", 2, [*base, "--out", REPO / "tests" / "never-written.json"])
    refuses("report-already-exists", "io", 2, [*base, "--out", outd / "report.json"])
    store2 = workdir / "store-tampered"
    store2.mkdir()
    for n in SOURCE_FILES:
        (store2 / n).write_bytes((store / n).read_bytes())
    raw = bytearray((store2 / "benchmark_data.json").read_bytes())
    raw[raw.index(b"INVENTED")] ^= 0x01                                   # a same-length one-bit change
    (store2 / "benchmark_data.json").write_bytes(bytes(raw))
    refuses("tampered-data", "tamper", 1, ["verify-pins", "--pins", paths["pins"], "--data", store2 / "benchmark_data.json",
                                           "--labels", store2 / "pr_labels.json"])
    write_json(store / "pins-copy.json", json.loads(paths["pins"].read_text()))
    refuses("pins-inside-store", "pins", 1, ["verify-pins", "--pins", store / "pins-copy.json", "--data", paths["data"],
                                             "--labels", paths["labels"]])
    refuses("wrong-expected-revision", "pins", 1, ["verify-pins", "--pins", paths["pins"], "--data", paths["data"],
                                                   "--labels", paths["labels"], "--expect-revision", "0" * 40])

    def bad(name, mutate, code="judgments"):
        ds = mutate([json.loads(json.dumps(d)) for d in docs])
        p = ops / f"bad-{name}.json"
        write_json(p, ds)
        refuses(name, code, 1, ["reference-score", "--pins", paths["pins"], "--data", paths["data"], "--labels",
                                paths["labels"], "--proposal", paths["proposal"], "--judgments", p, "--tools", *TOOLS,
                                "--out", outd / f"bad-{name}.json"])

    def wrong_digest(ds):
        ds[0]["duplicateGroups"]["candidateListSha256"] = "sha256:" + "0" * 64
        return ds

    def null_confidence(ds):
        ds[0]["pairs"][0]["confidence"] = None
        return ds

    def unrequested(ds):
        ds.append(dict(ds[0], tool="demo-c"))
        return ds

    def other_judge(ds):
        ds[1]["judge"]["model"] = "a-different-judge"
        return ds

    bad("wrong-candidate-digest", wrong_digest)
    bad("null-confidence", null_confidence)
    bad("document-for-unrequested-tool", unrequested)
    bad("mixed-judges", other_judge, "judge-mismatch")
    return {"workdir": str(workdir), "report": str(outd / "report.json"), "controls": controls, "log": log}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workdir", help="a new or empty directory outside reviewer/, fixtures/ and tests/ "
                                      "(default: a new temporary directory, kept so you can read the files)")
    args = ap.parse_args(argv)
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="pullo-benchmark-demo-"))
    log: list = []
    try:
        result = run(workdir, log)
    except AssertionError:
        print("\n".join(log), file=sys.stderr)
        print(f"demo FAILED; files kept in {workdir}", file=sys.stderr)
        return 1
    print("\n".join(log))
    print(f"\ndemo OK: {len(log)} checks. Invented data only; no network, provider, key or Git call was made.")
    print(f"files: {result['workdir']}  (store/ raw source, ops/ pins+proposal+judgments, out/ reports)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
