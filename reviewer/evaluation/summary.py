"""Plain-text local summary of an evaluation (also printed by the CLI)."""

from __future__ import annotations


def _usd(micros) -> str:
    return "n/a" if micros is None else f"${micros / 1e6:.6f}"


def _ratio(r) -> str:
    if r is None:
        return "n/a"
    if r.get("value") is None:
        return f"undefined ({r.get('undefinedReason')})"
    return f"{r['value']:.3f}" + (f" ({r['numerator']}/{r['denominator']})" if "numerator" in r else "")


def render_summary(*, mode, eval_run_id, out, report, cases, problems, manifest, ok) -> str:
    replay = mode == "strict-replay"
    lines = [f"smoke {'replay' if replay else 'record'}: {'OK' if ok else 'NOT OK'}  evalRunId {eval_run_id}  "
             f"mode {mode}", f"output {out}", ""]
    head = f"{'case':<10} {'status':<10} {'expect':<9} {'met':<4} {'TP':>2} {'FP':>2} {'FN':>2} {'dup':>3} " \
           f"{'cmts':>4}  {'orig ms':>7} {'replay ms':>9}  detail"
    lines += [head, "-" * len(head)]
    for c in cases:
        r = c.case_result
        detail = []
        if r["error"]:
            detail.append(f"error {r['error']['code']}")
        detail += [f"incomplete {i['reason']}@{i['stage']}" for i in r["incomplete"]]
        if c.comparison is not None:
            detail.append("replay equal" if c.comparison["equal"] else
                          "REPLAY DIFFERS: " + "; ".join(c.comparison["differences"][:3]))
        if not c.ran:
            detail.append("NO RUN")
        detail += [f"PROBLEM {p}" for p in c.problems[:3]]
        lat = r["latencyMs"]
        lines.append(f"{r['caseId']:<10} {r['status']:<10} {str(r['expect']):<9} "
                     f"{'yes' if r['expectationMet'] else 'NO':<4} {r['truePositives']:>2} {r['falsePositives']:>2} "
                     f"{r['falseNegatives']:>2} {r['duplicates']:>3} {r['comments']:>4}  "
                     f"{str(lat['original']):>7} {str(lat['replay']):>9}  {', '.join(detail)}")
    lines.append("")
    if report is not None:
        m, cov, cost = report["metrics"], report["coverage"], report["cost"]
        met = cov["expectationMet"]
        lines += [f"expectations met: {met}/{len(cases)}   coverage: completed {cov['completed']}, partial "
                  f"{cov['partial']}, failed {cov['failed']}, cancelled {cov['cancelled']}",
                  f"synthetic mechanics only (not review quality): precision {_ratio(m['precision'])}, "
                  f"recall {_ratio(m['recall'])}, f1 {_ratio(m['f1'])}",
                  f"cost: live calls {cost['liveCalls']}; " + ", ".join(
                      f"{b} {v['records']} rec/{_usd(v['usdMicros'])}" for b, v in cost["byBasis"].items()),
                  "  actual provider spend: $0 (synthetic provider only; synthetic prices are not spend)",
                  f"latency ms (original | replay): p50 {report['latency']['original']['p50']} | "
                  f"{report['latency']['replay']['p50']}, max {report['latency']['original']['max']} | "
                  f"{report['latency']['replay']['max']}"]
    else:
        lines.append("EvalReport: NOT WRITTEN (did not validate; see problems)")
    lines += ["", "provenance:",
              f"  suite {manifest['suite']['id']}@{manifest['suite']['version']} digest {manifest['suite']['digest']}",
              f"  configDigest {manifest['configDigest']}",
              f"  profile {manifest['profile']['ref']} {manifest['profile']['digest']}  plan v{manifest['plan']['version']} "
              f"{manifest['plan']['digest']}",
              f"  versions {', '.join(f'{k} {v}' for k, v in manifest['versions'].items())}"]
    if "authorization" in manifest:
        a, b = manifest["authorization"], manifest["spendBook"]
        lines += [f"  authorization {a['id']} {a['digest']} providers {a['providers']}",
                  f"  spend book {b['path']} committed {b['totals']['committed']} inflight {b['totals']['inflight']} "
                  f"limit {b['totals']['limit']} (usdMicros, synthetic)"]
    if "recording" in manifest:
        r = manifest["recording"]
        lines.append(f"  replay of {r['evalRunId']} pinned by {r['pinSource']} {r['manifestDigest']}")
    lines += ["  report report.json, pins eval.json, per-case outcomes/, runs/<runId>/ (trace, artifacts, "
              "comments.json, review.md)"]
    if problems:
        lines += ["", "problems:"] + [f"  {p}" for p in problems]
    lines += ["", "limits: synthetic smoke verifies mechanics only; no resume/stage-replay CLI in this slice."]
    return "\n".join(lines) + "\n"
