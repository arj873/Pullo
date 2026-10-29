"""The fixed read-only operations. Pure functions of (view, limits, normalized args).

The four base tools, plus impact mode's `find_references` (model-requestable, whole-word, regex-free) and the
host-only `impact_scan` pre-pass (definition heuristics from reviewer.impactmap). Both scans use the same file, byte
and wall caps as search_literal; they skip decoding a verified file whose bytes contain none of the names (speed
only: such a file cannot match).

Every file read goes through snapshot.read_verified, so the bytes are checked against the pinned
manifest hash on EVERY read. Text is redacted (contracts redact) before it is split into lines,
so excerpts equal what snapshot.excerpt_matches expects, and a secret can neither be shown nor
found by search. `resolved: true` is set only after the contracts' snapshot resolver agrees.
"""

from __future__ import annotations

import difflib
import json
import os
import stat
from dataclasses import dataclass, field

from reviewer.contracts.redaction import redact
from reviewer.contracts.snapshot import SnapshotError, read_verified

from reviewer import impactmap as impact

from . import policy
from .words import word_hits
from .view import View


@dataclass
class Limits:
    max_calls: int = 50               # tool calls per session (per agent)
    wall_s: float = 120.0             # session wall time (INVESTIGATE ceiling is 120 s)
    max_list: int = 500               # entries returned by list_files
    max_file_bytes: int = 1 << 20     # larger files are not read, listed as too large
    max_read_lines: int = 400
    max_output_chars: int = 24_000    # model-visible excerpt characters per result
    chunk_chars: int = 6_000          # per Evidence excerpt (contract allows 8000)
    max_line_chars: int = 2_000       # longer lines cannot be shown exactly and are omitted
    max_search_files: int = 1_000
    max_search_scan_bytes: int = 16 << 20
    max_search_results: int = 50
    max_matches_per_file: int = 10
    max_query_chars: int = 200
    max_diff_lines: int = 800
    max_diff_input_lines: int = 5_000
    search_wall_s: float | None = None   # per-search wall budget; None = only the session wall applies (legacy)

    @classmethod
    def full_repository(cls, **tighter) -> "Limits":
        """Trusted host profile for a complete pinned tree (up to 60k searched files, 256 MiB scanned).
        Overrides may only tighten; a larger or unknown value is a host error (ValueError)."""
        prof = cls(max_calls=60, wall_s=300.0, search_wall_s=90.0, max_search_files=FULL_REPO_SEARCH_FILES,
                   max_search_scan_bytes=FULL_REPO_SCAN_BYTES)
        for k, v in tighter.items():
            cur = getattr(prof, k, None)
            if not hasattr(prof, k) or isinstance(cur, bool) or not isinstance(v, (int, float)) \
                    or isinstance(v, bool) or not 0 < v <= cur:
                raise ValueError(f"limit {k!r}: overrides may only tighten the full-repository profile")
            setattr(prof, k, v)
        return prof


FULL_REPO_SEARCH_FILES = 60_000
FULL_REPO_SCAN_BYTES = 256 << 20


@dataclass
class Outcome:
    status: str
    evidence: list = field(default_factory=list)
    completeness: str = "exact"
    truncated: dict | None = None
    notice: str = ""
    redactions: dict = field(default_factory=dict)
    layers: list = field(default_factory=list)
    incomplete: str | None = None        # INCOMPLETE_REASONS value if a cap ended the work early

    def result(self) -> dict:
        return {"status": self.status, "evidence": self.evidence, "completeness": self.completeness,
                "truncated": self.truncated, "notice": self.notice[:2000]}


class Ctx:
    def __init__(self, view: View, limits: Limits, tool_call_id: str, clock, started: float):
        self.view, self.limits, self.tcid = view, limits, tool_call_id
        self.clock, self.started = clock, started
        self.resolve = view.resolver()
        self.tampered = False

    def expired(self) -> bool:
        return self.clock() - self.started >= self.limits.wall_s

    def note(self) -> str:
        return self.view.note()


DENIED = Outcome("denied", notice="That request is not permitted.")


def _add(total: dict, counts: dict) -> None:
    for k, n in counts.items():
        total[k] = total.get(k, 0) + n


# ---------------------------------------------------------------- verified loading

def load_text(ctx: Ctx, side: str, path: str):
    """-> (layer, lines, counts, None) or (layer|None, None, {}, Outcome) explaining why not."""
    layer, data, fail = load_bytes(ctx, side, path)
    if fail is not None:
        return layer, None, {}, fail
    return decode_text(layer, path, data)


def load_bytes(ctx: Ctx, side: str, path: str):
    """The verified bytes of a pinned file: -> (layer, data, None) or (layer|None, None, Outcome)."""
    found = ctx.view.find(side, path)
    if found is None:
        return None, None, Outcome(
            "unavailable", completeness="approximate" if ctx.view.approximate else "exact",
            notice=(f"{path!r} is not in the {side} snapshot view. {ctx.note()}").strip())
    layer, entry = found
    if entry["type"] == "symlink":
        return layer, None, DENIED
    if entry["size"] > ctx.limits.max_file_bytes:
        return layer, None, Outcome("unavailable", layers=[layer.name],
                                    notice=f"{path!r} is {entry['size']} bytes; limit is {ctx.limits.max_file_bytes}.")
    full = os.path.join(layer.root, path)
    try:
        st = os.stat(full, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_size > ctx.limits.max_file_bytes:
            raise SnapshotError("not the pinned regular file")
        data = read_verified(layer.root, layer.manifest, path, max_bytes=ctx.limits.max_file_bytes)
    except (SnapshotError, OSError):
        ctx.tampered = True
        return layer, None, Outcome(
            "error", layers=[layer.name],
            notice=f"{path!r} no longer matches its pinned snapshot; nothing was read from it.")
    return layer, data, None


def decode_text(layer, path: str, data: bytes):
    """Verified bytes -> (layer, redacted lines, counts, None) or (layer, None, {}, Outcome)."""
    if b"\x00" in data[:8192]:
        return layer, None, {}, Outcome("unavailable", layers=[layer.name], notice=f"{path!r} is binary; text not shown.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return layer, None, {}, Outcome("unavailable", layers=[layer.name], notice=f"{path!r} is not UTF-8; text not shown.")
    red, counts = redact(text)
    lines = red.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return layer, lines, counts, None


def _code_evidence(ctx: Ctx, layer, path: str, a: int, b: int, lines: list[str], source: str):
    ev = {"kind": "code", "path": path, "lines": [a, b], "commit": layer.snapshot_id,
          "excerpt": "\n".join(lines[a - 1:b]), "source": source, "toolCallId": ctx.tcid}
    if ctx.resolve(ev) is not True:
        return None
    ev["resolved"] = True
    return ev


def _text_chunks(ctx: Ctx, header: str, rows: list[str], source: str) -> tuple[list[dict], int]:
    """tool-result Evidence chunks of whole rows within the char caps. Returns (evidence, rows shown)."""
    lim, out, cur, used, shown = ctx.limits, [], [header], len(header), 0
    for row in rows:
        if used + len(row) + 1 > lim.max_output_chars:
            break
        if sum(len(x) + 1 for x in cur) + len(row) + 1 > lim.chunk_chars and len(cur) > 0:
            out.append(cur)
            cur = []
        cur.append(row)
        used += len(row) + 1
        shown += 1
    out.append(cur)
    return [{"kind": "tool-result", "excerpt": "\n".join(c), "source": source, "toolCallId": ctx.tcid}
            for c in out if c], shown


# ---------------------------------------------------------------- list_files

def _in_prefix(path: str, prefix: str) -> bool:
    return prefix == "" or path == prefix or path.startswith(prefix + "/")


def list_files(ctx: Ctx, a: dict) -> Outcome:
    side, prefix, limit = a["side"], a["prefix"], min(a["limit"], ctx.limits.max_list)
    after = a.get("after")                      # paging cursor: last path of the previous page
    rows = []
    for layer in ctx.view.layers(side):
        for p, e in layer._index.items():
            if policy.permitted(p) and _in_prefix(p, prefix) and (after is None or p > after):
                rows.append((p, f"{p}  [symlink, not readable]" if e["type"] == "symlink" else f"{p}  ({e['size']} bytes)"))
    rows.sort()
    total = len(rows)
    page = rows[:limit]
    cov = ("partial view (changed files and selected context)" if ctx.view.partial else
           "full snapshot with import omissions" if ctx.view.omitted else "full snapshot")
    where = prefix or "/"
    if after is None:
        header = f"# {side} files under {where}: {len(page)} of {total}; {cov}"
    else:
        header = f"# {side} files under {where} after {json.dumps(after, ensure_ascii=False)}: {total} remaining; {cov}"
    ev, shown = _text_chunks(ctx, header, [r for _, r in page], "list_files")
    truncated = {"shown": shown, "total": total} if shown < total else None
    status = "empty" if total == 0 else ("partial" if truncated else "ok")
    notes = []
    if truncated and shown:
        nxt = {"side": side, "prefix": prefix, "after": page[shown - 1][0], "limit": a["limit"]}
        notes.append("Next page: list_files " + json.dumps(nxt, ensure_ascii=False))
    elif truncated:
        notes.append("Output cap is too small to show even one entry; no continuation can be offered.")
    if truncated:
        notes.append(f"{shown} of {total} entries shown.")
    elif after is not None:
        notes.append("Last page." if total else "No entries after the cursor.")
    notes.append(ctx.note())
    return Outcome(status, ev, "exact" if not ctx.view.approximate and not truncated else "approximate",
                   truncated, " ".join(x for x in notes if x),
                   layers=[l.name for l in ctx.view.layers(side)])


# ---------------------------------------------------------------- read_file

def read_file(ctx: Ctx, a: dict) -> Outcome:
    side, path = a["side"], a["path"]
    if not policy.permitted(path):
        return DENIED
    layer, lines, counts, fail = load_text(ctx, side, path)
    if fail is not None:
        return fail
    n, lim = len(lines), ctx.limits
    start = a["start_line"]
    if start > max(n, 1) or n == 0:
        return Outcome("empty", layers=[layer.name], redactions=counts,
                       notice=f"{path} has {n} line(s); nothing at line {start}.")
    end = min(a["end_line"] if a["end_line"] is not None else start + lim.max_read_lines - 1,
              n, start + lim.max_read_lines - 1)
    ev, omitted, used, i, shown_to = [], [], 0, start, start - 1
    chunk_start = None
    while i <= end:
        ln = lines[i - 1]
        if len(ln) > lim.max_line_chars:
            if chunk_start is not None:
                e = _code_evidence(ctx, layer, path, chunk_start, i - 1, lines, "read_file")
                ev.append(e)
                chunk_start = None
            omitted.append(i)
            i += 1
            continue
        size_now = sum(len(x) + 1 for x in lines[chunk_start - 1:i - 1]) if chunk_start is not None else 0
        if used + len(ln) + 1 > lim.max_output_chars:
            break
        if chunk_start is not None and size_now + len(ln) + 1 > lim.chunk_chars:
            ev.append(_code_evidence(ctx, layer, path, chunk_start, i - 1, lines, "read_file"))
            chunk_start = None
        if chunk_start is None:
            chunk_start = i
        used += len(ln) + 1
        shown_to = i
        i += 1
    if chunk_start is not None:
        ev.append(_code_evidence(ctx, layer, path, chunk_start, shown_to, lines, "read_file"))
    if any(e is None for e in ev):
        ctx.tampered = True
        return Outcome("error", layers=[layer.name],
                       notice=f"{path!r} lines could not be resolved against the pinned snapshot.")
    asked_end = a["end_line"] if a["end_line"] is not None else n
    requested = max(0, min(asked_end, n) - start + 1)
    shown_lines = sum(e["lines"][1] - e["lines"][0] + 1 for e in ev)
    trunc = shown_lines < requested or bool(omitted) or end < min(asked_end, n)
    parts = [f"{path} lines {start}-{shown_to} of {n} from {layer.label(path)} ({layer.snapshot_id[:24]}...)."]
    if omitted:
        parts.append(f"{len(omitted)} line(s) longer than {lim.max_line_chars} chars omitted (first at line {omitted[0]}).")
    if shown_lines < requested and not omitted:
        parts.append("Output cap reached; request a later line range.")
    parts.append(ctx.note())
    return Outcome("partial" if trunc else "ok", ev, "exact",
                   {"shown": shown_lines, "total": requested} if trunc else None,
                   " ".join(x for x in parts if x), counts, [layer.name])


# ---------------------------------------------------------------- search_literal

def search_literal(ctx: Ctx, a: dict) -> Outcome:
    side, q, prefix = a["side"], a["query"], a["prefix"]
    lim = ctx.limits
    needle = q if a["case_sensitive"] else q.casefold()
    cap = min(a["limit"], lim.max_search_results)
    files = []
    for layer in ctx.view.layers(side):
        for p in layer._index:
            if policy.permitted(p) and _in_prefix(p, prefix):    # policy-hidden paths leave no trace (no existence hint)
                files.append((p, layer))
    files.sort(key=lambda t: t[0])
    t_search = ctx.clock()
    ev, counts_total = [], {}
    scanned = skipped_big = skipped_text = failed = long_hits = visited = symlinks = 0
    matches = over_file_cap = 0          # matching lines seen in searched files / files above the per-file cap
    stop = None
    for p, layer in files:
        e = layer.entry(p)
        if e["type"] == "symlink":
            symlinks += 1
            continue
        if ctx.expired():
            stop = "deadline"
            break
        if lim.search_wall_s is not None and ctx.clock() - t_search >= lim.search_wall_s:
            stop = "search time cap"
            break
        if e["size"] > lim.max_file_bytes:     # never read, so it must not spend the file or byte budget
            skipped_big += 1
            continue
        if visited >= lim.max_search_files:
            stop = "search file cap"
            break
        if scanned + e["size"] > lim.max_search_scan_bytes:
            stop = "search byte cap"
            break
        visited += 1
        scanned += e["size"]
        lyr, lines, counts, fail = load_text(ctx, side, p)
        if fail is not None:
            if fail.status == "error":
                failed += 1
            else:
                skipped_text += 1
            continue
        _add(counts_total, counts)
        hits = found = 0
        for n, ln in enumerate(lines, 1):
            hay = ln if a["case_sensitive"] else ln.casefold()
            if needle not in hay:
                continue
            if len(ln) > lim.max_line_chars:
                long_hits += 1
                continue
            found += 1
            matches += 1
            if len(ev) >= cap or hits >= lim.max_matches_per_file:
                continue                  # counted, not shown
            item = _code_evidence(ctx, lyr, p, n, n, lines, "search_literal")
            if item is None:
                failed += 1
                continue
            ev.append(item)
            hits += 1
        if found > lim.max_matches_per_file:
            over_file_cap += 1
    chars = 0
    kept = []
    output_capped = False
    for item in ev:                       # model-visible output cap
        chars += len(item["excerpt"]) + len(item["path"])
        if chars > lim.max_output_chars:
            output_capped = True
            break
        kept.append(item)
    ev = kept
    shown = len(ev)
    unshown = matches - shown
    # The total is exact only if every candidate file was searched and verified.
    exact_total = stop is None and not failed
    notes = []
    if stop:
        notes.append(f"Search stopped early ({stop}); results are incomplete: {visited} of {len(files)} candidate "
                     f"file(s) visited, {scanned} bytes scanned, later files in path order were not searched.")
    if unshown > 0:
        why = ", ".join(x for x in (f"result cap {cap}" if matches > cap else "",
                                    f"per-file cap {lim.max_matches_per_file} ({over_file_cap} file(s))" if over_file_cap else "",
                                    "output size cap" if output_capped else "") if x)
        if exact_total:
            notes.append(f"{shown} of {matches} matching lines shown ({why}); results are incomplete, narrow the query or prefix.")
        else:
            notes.append(f"{shown} matching lines shown, capped ({why}); at least {matches} exist but the "
                         "total is unknown because the search did not finish.")
    if skipped_big or skipped_text:
        notes.append(f"{skipped_big} oversized and {skipped_text} binary/non-UTF-8 file(s) skipped.")
    if symlinks:
        notes.append(f"{symlinks} symlink(s) in scope were not searched (links are never followed).")
    if failed:
        ctx.tampered = True
        notes.append(f"{failed} file(s) failed pinned-snapshot verification and were skipped.")
    if long_hits:
        notes.append(f"{long_hits} match(es) on lines longer than {lim.max_line_chars} chars not shown.")
    if ctx.note():
        notes.append(ctx.note())
    complete = not (stop or skipped_big or skipped_text or failed or long_hits or symlinks or unshown > 0)
    status = "error" if failed and not ev else ("partial" if not complete else ("ok" if ev else "empty"))
    trunc = {"shown": shown, "total": matches} if unshown > 0 and exact_total else None
    return Outcome(status, ev, "exact" if complete and not ctx.view.approximate else "approximate", trunc,
                   " ".join(notes), counts_total, [l.name for l in ctx.view.layers(side)],
                   "deadline" if stop == "deadline" else None)


# ---------------------------------------------------------------- diff

def _changed_index(view: View, side: str) -> dict:
    idx = {}
    for layer in view.layers(side):
        idx.update({p: e for p, e in layer._index.items()
                    if layer.path_kind(p) in ("full", "changed") and policy.permitted(p)})
    return idx


def diff(ctx: Ctx, a: dict) -> Outcome:
    path = a["path"]
    lim = ctx.limits
    if path is None:
        b, h = _changed_index(ctx.view, "base"), _changed_index(ctx.view, "head")
        rows = []
        for p in sorted(set(b) | set(h)):
            if p not in b:
                rows.append(f"A {p}")
            elif p not in h:
                rows.append(f"D {p}")
            elif b[p]["sha256"] != h[p]["sha256"] or b[p]["type"] != h[p]["type"]:
                rows.append(f"M {p}")
        total = len(rows)
        rows = rows[:lim.max_list]
        ev, shown = _text_chunks(ctx, f"# changed paths ({len(rows)} of {total}); A added, D deleted, M modified", rows, "diff")
        trunc = {"shown": shown, "total": total} if shown < total else None
        notes = [ctx.note() and "Context files are excluded from this list.", ctx.note(),
                 f"{shown} of {total} paths shown." if trunc else ""]
        return Outcome("empty" if total == 0 else ("partial" if trunc else "ok"), ev,
                       "exact" if not ctx.view.approximate and not trunc else "approximate", trunc,
                       " ".join(x for x in notes if x), layers=[l.name for s in ("base", "head") for l in ctx.view.layers(s)])
    if not policy.permitted(path):
        return DENIED
    fb, fh = ctx.view.find("base", path), ctx.view.find("head", path)
    if fb is None and fh is None:
        return Outcome("unavailable", completeness="approximate" if ctx.view.approximate else "exact",
                       notice=f"{path!r} is in neither snapshot view. {ctx.note()}".strip())
    # A one-sided file is only "added"/"removed" if the missing side is known to be complete for it.
    for found, other, side in ((fb, fh, "head"), (fh, fb, "base")):
        if found is not None and other is None and found[0].path_kind(path) == "context":
            return Outcome("unavailable", completeness="approximate",
                           notice=f"Cannot diff {path!r}: it is context loaded on one side only, so its "
                                  f"absence on the {side} side is unknown. {ctx.note()}".strip())
    layers, texts, counts_total = [], {}, {}
    for side, found in (("base", fb), ("head", fh)):
        if found is None:
            texts[side] = []
            continue
        lyr, lines, counts, fail = load_text(ctx, side, path)
        if fail is not None:
            return fail
        if len(lines) > lim.max_diff_input_lines:
            return Outcome("unavailable", layers=[lyr.name], notice=f"{path!r} has too many lines to diff.")
        _add(counts_total, counts)
        texts[side] = lines
        layers.append(lyr)
    mode = ""
    if fb and fh and fb[1]["sha256"] == fh[1]["sha256"]:
        if fb[1]["type"] == fh[1]["type"]:
            return Outcome("empty", layers=[l.name for l in layers], notice=f"{path!r} is identical in base and head.")
        mode = f"; mode changed {fb[1]['type']} -> {fh[1]['type']}, contents identical"
    elif fb and fh and fb[1]["type"] != fh[1]["type"]:
        mode = f"; mode changed {fb[1]['type']} -> {fh[1]['type']}"
    ids = {s: f[0].snapshot_id[:24] + "..." if f else "absent" for s, f in (("base", fb), ("head", fh))}
    body = list(difflib.unified_diff(texts["base"], texts["head"], f"base/{path}", f"head/{path}", n=3, lineterm=""))
    rows = [r for r in body if len(r) <= lim.max_line_chars][:lim.max_diff_lines]
    skipped = len(body) - len(rows)
    header = f"# diff {path}; base {ids['base']}; head {ids['head']}{mode}"
    ev, shown = _text_chunks(ctx, header, rows, "diff")
    trunc = {"shown": shown, "total": len(body)} if shown < len(body) else None
    notes = [f"{skipped} diff line(s) not shown (cap or over-long)." if trunc else "", ctx.note()]
    return Outcome("partial" if trunc else "ok", ev, "approximate" if ctx.view.omitted else "exact", trunc, " ".join(x for x in notes if x),
                   counts_total, [l.name for l in layers])


# ---------------------------------------------------------------- whole-word reference scans (impact mode)

class ScanAbort(Exception):
    """The wall-clock safety limit was hit: the call fails explicitly and returns nothing (never a partial result)."""


def _safety(ctx: Ctx, t0: float) -> None:
    if ctx.expired() or ctx.clock() - t0 >= impact.SAFETY_WALL_S:
        raise ScanAbort


def _aborted(ctx: Ctx, what: str) -> Outcome:
    return Outcome("error", notice=f"{what} aborted at the wall-clock safety limit; no partial result is returned "
                                   "(scans stop only on deterministic caps otherwise).", incomplete="deadline")


def _ref_scan(ctx: Ctx, side: str, prefix: str, names: list, max_chars: int, t0: float,
              exclude=lambda p, n, names: False, *, name_hits: int | None = None, name_decoded: int | None = None):
    """Count whole-word matches of `names` in every permitted text file under `prefix` of `side`, in (code, tests,
    other; path) order. Stops ONLY on deterministic caps, so the same snapshot and limits always give the same
    result; the wall clock can only abort (ScanAbort). No evidence is built here.

    Each name has its own share (`name_hits` reference lines, `name_decoded` bytes decoded for files whose bytes
    contain it): a name past its share is dropped from the rest of the scan and recorded in `cut`, and the other
    names keep scanning. Whole-scan caps (files, bytes verified, bytes decoded, hits) stop everything and cut every
    name still active. -> (hits [(path, line, [names])], stats (stats["cut"] = {name: reason}), redaction counts)."""
    lim = ctx.limits
    max_files = min(lim.max_search_files, impact.SCAN_MAX_FILES)
    max_bytes = min(lim.max_search_scan_bytes, impact.SCAN_MAX_BYTES)
    name_hits = impact.SCAN_MAX_HITS if name_hits is None else name_hits
    name_decoded = impact.SCAN_MAX_DECODED_BYTES if name_decoded is None else name_decoded
    files = sorted(((p, layer) for layer in ctx.view.layers(side) for p in layer._index
                    if policy.permitted(p) and _in_prefix(p, prefix)),
                   key=lambda t: (impact.ref_sort_key(t[0], 0)[0], t[0]))
    st = {"candidates": len(files), "visited": 0, "scanned": 0, "decoded": 0, "skippedBig": 0, "skippedText": 0,
          "failed": 0, "symlinks": 0, "longLines": 0, "stop": None, "cut": {}}
    hits, counts_total = [], {}
    active = list(names)
    needle = {nm: nm.encode("utf-8") for nm in names}
    n_hits = {nm: 0 for nm in names}
    n_dec = {nm: 0 for nm in names}

    def cut(nm, reason):
        if nm in active:
            active.remove(nm)
            st["cut"][nm] = reason

    for p, layer in files:
        if not active:
            break
        _safety(ctx, t0)
        e = layer.entry(p)
        if e["type"] == "symlink":
            st["symlinks"] += 1
            continue
        if e["size"] > lim.max_file_bytes:
            st["skippedBig"] += 1
            continue
        if st["visited"] >= max_files:
            st["stop"] = "file cap"
            break
        if st["scanned"] + e["size"] > max_bytes:
            st["stop"] = "byte cap"
            break
        st["visited"] += 1
        st["scanned"] += e["size"]
        lyr, data, fail = load_bytes(ctx, side, p)          # verified against the pinned manifest, as every read
        present = [] if fail is not None else [nm for nm in active if needle[nm] in data]
        if fail is None and not present and b"\x00" not in data[:8192]:
            continue        # no symbol bytes at all: nothing to count, so skip decoding and redaction
        if fail is None:
            if st["decoded"] + len(data) > impact.SCAN_MAX_DECODED_BYTES:
                st["stop"] = "decoded-byte cap"
                break
            st["decoded"] += len(data)
            for nm in present:
                n_dec[nm] += len(data)
            lyr, lines, counts, fail = decode_text(lyr, p, data)
        if fail is not None:
            st["failed" if fail.status == "error" else "skippedText"] += 1
            continue
        _add(counts_total, counts)
        blob = "\n".join(lines)
        here = [nm for nm in present if nm in blob]
        for n, ln in enumerate(lines, 1):
            if not here:
                break
            on_line = word_hits(ln, here)
            if not on_line or exclude(p, n, on_line):
                continue
            if len(ln) > max_chars:
                st["longLines"] += 1
                continue
            if len(hits) >= impact.SCAN_MAX_HITS:
                st["stop"] = "hit cap"
                break
            hits.append((p, n, on_line))
            for nm in on_line:
                n_hits[nm] += 1
                if n_hits[nm] >= name_hits:
                    cut(nm, "per-name hit share")
                    here.remove(nm)
        if st["stop"]:
            break
        for nm in present:
            if n_dec[nm] > name_decoded:
                cut(nm, "per-name decoded-byte share")
    if st["stop"]:
        for nm in list(active):
            cut(nm, st["stop"])
    if st["failed"]:
        ctx.tampered = True
    return hits, st, counts_total


def _materialize(ctx: Ctx, side: str, wanted: list, source: str, t0: float) -> tuple[dict, int]:
    """Resolved code evidence + enclosing header for exactly the (path, line) pairs that will be shown, re-read
    through the verified loader. -> ({(path, line): (item, header|None)}, failures)."""
    out, failed, by_path = {}, 0, {}
    for p, n in wanted:
        by_path.setdefault(p, []).append(n)
    for p in sorted(by_path):
        _safety(ctx, t0)
        lyr, lines, _, fail = load_text(ctx, side, p)
        if fail is not None:
            failed += 1
            continue
        for n in sorted(set(by_path[p])):
            item = _code_evidence(ctx, lyr, p, n, n, lines, source) if n <= len(lines) else None
            if item is None:
                failed += 1
                continue
            out[(p, n)] = (item, impact.enclosing_header(p, lines, n))
    if failed:
        ctx.tampered = True
    return out, failed


def _scan_notes(st: dict, ctx: Ctx) -> list[str]:
    notes = []
    shares = sorted((nm, why) for nm, why in st.get("cut", {}).items() if why.startswith("per-name"))
    if shares:
        notes.append(f"{len(shares)} name(s) used up their per-name scan share and were dropped from the rest of the "
                     "scan (their counts are lower bounds; other names kept scanning): "
                     + ", ".join(f"{nm} ({why})" for nm, why in shares[:20]) + ".")
    if st["stop"]:
        notes.append(f"Scan stopped at its {st['stop']} (deterministic); counts are lower bounds: {st['visited']} of "
                     f"{st['candidates']} candidate file(s) visited, later files in path order were not searched.")
    if st["skippedBig"] or st["skippedText"]:
        notes.append(f"{st['skippedBig']} oversized and {st['skippedText']} binary/non-UTF-8 file(s) skipped.")
    if st["symlinks"]:
        notes.append(f"{st['symlinks']} symlink(s) in scope were not searched (links are never followed).")
    if st["failed"]:
        notes.append(f"{st['failed']} file(s) failed pinned-snapshot verification and were skipped.")
    if st["longLines"]:
        notes.append(f"{st['longLines']} match(es) on over-long lines counted but not shown.")
    if ctx.note():
        notes.append(ctx.note())
    return notes


def _q(text: str) -> str:
    """Repository text inside a host-written row: one JSON string (quotes and escapes, no newline, no backtick), so
    it can never pass for a host row such as a count line or a section header."""
    return json.dumps(text.replace("`", "'").replace("\n", " ").replace("\r", " ")[:impact.MAX_HEADER_CHARS],
                      ensure_ascii=False)


def _qp(path: str) -> str:
    """A repository path inside a host-written row, JSON-quoted (paths are repository data too)."""
    return json.dumps(path, ensure_ascii=False)


def _hdr(h) -> str:
    return "" if h is None else f" in {_q(h[1])} (L{h[0]})"


def find_references(ctx: Ctx, a: dict) -> Outcome:
    """Whole-word identifier references of one symbol, paginated by `offset` in (code, tests, other; path; line)
    order. Item 0 is the listing (path:line and enclosing definition per item); items 1.. are the matching lines as
    resolved code evidence (citable). Only the requested page is materialized; the rest is counted."""
    side, sym, prefix = a["side"], a["symbol"], a["path_prefix"]
    lim = ctx.limits
    limit, offset = min(a["limit"], lim.max_search_results), a["offset"]
    t0 = ctx.clock()
    try:
        hits, st, counts = _ref_scan(ctx, side, prefix, [sym], lim.max_line_chars, t0)
        order = sorted(hits, key=lambda h: impact.ref_sort_key(h[0], h[1]))
        page = order[offset:offset + limit]
        got, mfail = _materialize(ctx, side, [(h[0], h[1]) for h in page], "find_references", t0)
    except ScanAbort:
        return _aborted(ctx, "find_references")
    st["failed"] += mfail
    total, files = len(order), len({h[0] for h in order})
    rows, ev, used = [], [], 0
    for h in page:
        if (h[0], h[1]) not in got:
            continue
        item, hdr = got[(h[0], h[1])]
        d = impact.def_on_line(impact.language_of(h[0]), item["excerpt"])
        tag = " (definition)" if d is not None and d[0] == sym else ""
        row = f"[{len(ev) + 1}] {_qp(h[0])}:{h[1]}{tag}{_hdr(hdr)}"
        if used + len(row) + len(item["excerpt"]) + 2 > lim.max_output_chars - 600:
            break
        used += len(row) + len(item["excerpt"]) + 2
        rows.append(row)
        ev.append(item)
    shown = len(ev)
    complete_scan = st["stop"] is None and not st["failed"] and not st["cut"]
    where = f" under {prefix}/" if prefix else ""
    head = (f"# references to `{sym}` ({side}, whole word{where}): {total}{'' if complete_scan else '+'} line(s) in "
            f"{files} file(s); references {offset + 1 if shown else 0}-{offset + shown} of that order (code, tests, other "
            f"files) shown below as result items [1]-[{shown}]")
    listing = "\n".join([head] + rows)[:7_900]
    evidence = [{"kind": "tool-result", "excerpt": listing, "source": "find_references", "toolCallId": ctx.tcid}] + ev
    notes = []
    more = offset + shown < total
    if more and shown:
        nxt = {"side": side, "symbol": sym, "path_prefix": prefix, "limit": a["limit"], "offset": offset + shown}
        notes.append("Next page: find_references " + json.dumps(nxt, ensure_ascii=False))
    elif offset and not shown and total:
        notes.append(f"Offset {offset} is past the last of {total} reference(s).")
    notes += _scan_notes(st, ctx)
    complete = complete_scan and not more and offset == 0 and not (st["skippedBig"] or st["skippedText"]
                                                                   or st["symlinks"] or st["longLines"])
    trunc = {"shown": shown, "total": total} if (more or offset) and complete_scan else None
    status = "error" if st["failed"] and not ev else ("ok" if complete and total else
                                                     ("empty" if complete else "partial"))
    return Outcome(status, evidence, "exact" if complete and not ctx.view.approximate else "approximate", trunc,
                   " ".join(notes), counts, [l.name for l in ctx.view.layers(side)])


IMPACT_HEADER = ("# impact map ({side}): {n} changed symbol(s) analysed of {found} found in {files_ch} changed "
                 "file(s); {refs}{plus} reference(s) in {rfiles} file(s) outside the changed lines; {shown} shown; "
                 "truncated: {trunc}")


def _extract(ctx: Ctx, changed: list, b: dict, h: dict, t0: float):
    """Definition phase under deterministic caps: generated/lockfiles and files over max_diff_input_lines are
    skipped, at most MAX_CHANGED_FILES files and MAX_ANALYSED_LINES lines are analysed. -> (symbols, head changed
    lines per path, {skip reason: [paths]})."""
    max_lines = min(ctx.limits.max_diff_input_lines, impact.MAX_FILE_LINES)
    syms, head_changed, skipped, analysed = [], {}, {}, 0
    for k, p in enumerate(changed):
        _safety(ctx, t0)
        if k >= impact.MAX_CHANGED_FILES:
            skipped.setdefault("changed-file cap", []).extend(changed[k:])
            break
        if impact.language_of(p) is None:
            continue
        if impact.is_generated(p):
            skipped.setdefault("lockfile, generated or minified", []).append(p)
            continue
        texts, reason = {}, None
        for side, idx in (("base", b), ("head", h)):
            texts[side] = None
            if p not in idx:
                continue
            _, lines, _, fail = load_text(ctx, side, p)
            if fail is not None:
                reason = "unreadable or binary"
            elif len(lines) > max_lines:
                reason = f"over {max_lines} lines"
            texts[side] = lines
        n_lines = len(texts["base"] or []) + len(texts["head"] or [])
        if reason is None and analysed + n_lines > impact.MAX_ANALYSED_LINES:
            reason = f"analysis line cap {impact.MAX_ANALYSED_LINES}"
        if reason is not None:
            skipped.setdefault(reason, []).append(p)
            continue
        analysed += n_lines
        found, hc = impact.file_symbols(p, texts["base"], texts["head"])
        syms += found
        head_changed[p] = hc
    return syms, head_changed, skipped


def impact_scan(ctx: Ctx, a: dict) -> Outcome:
    """Host-only pre-pass (never offered to a model): definitions the change touches, and their whole-word
    references in the head snapshot outside the changed lines. Item 0 is the impact map; items 1.. are the shown
    reference lines as resolved code evidence. Deterministic: only caps stop it; the wall clock can only abort."""
    lim = ctx.limits
    t0 = ctx.clock()
    b, h = _changed_index(ctx.view, "base"), _changed_index(ctx.view, "head")
    changed = [p for p in sorted(set(b) | set(h))
               if p not in b or p not in h or b[p]["sha256"] != h[p]["sha256"]]
    try:
        syms, head_changed, skipped = _extract(ctx, changed, b, h, t0)
        selected, rest = impact.select(syms)
        own = {(s.path, s.line) for s in selected if s.side == "head"}
        names = [s.name for s in selected]

        def exclude(p, n, on_line):
            return n in head_changed.get(p, ()) or (p, n) in own

        hits, st, counts = (([], {"stop": None, "failed": 0, "skippedBig": 0, "skippedText": 0, "symlinks": 0,
                                  "longLines": 0, "visited": 0, "candidates": 0, "cut": {}}, {}) if not selected else
                            _ref_scan(ctx, "head", "", names, impact.MAX_REF_LINE_CHARS, t0, exclude,
                                      name_hits=impact.NAME_MAX_HITS, name_decoded=impact.NAME_MAX_DECODED_BYTES))
        per = {s.name: [] for s in selected}
        for hit in hits:
            for nm in hit[2]:
                if nm in per:
                    per[nm].append(hit)
        for nm in per:
            per[nm].sort(key=lambda x: impact.ref_sort_key(x[0], x[1]))
        plan, budget = {}, impact.MAX_REFS_SHOWN            # which refs each symbol may show, in symbol order
        for s in selected:
            plan[s.name] = per[s.name][:min(impact.MAX_REFS_PER_SYMBOL_SHOWN, budget)]
            budget -= len(plan[s.name])
        got, mfail = _materialize(ctx, "head", [(r[0], r[1]) for v in plan.values() for r in v], "impact_scan", t0)
    except ScanAbort:
        return _aborted(ctx, "impact_scan")
    st["failed"] += mfail
    rows, ev, used = [], [], 0
    all_files = {hit[0] for hit in hits}
    total_refs = sum(len(v) for v in per.values())
    full = False
    for s in selected:
        refs = per[s.name]
        files = {r[0] for r in refs}
        where = f"{'base ' if s.side == 'base' else ''}{_qp(s.path)}:{s.line}"
        rows.append(f"## {s.name} ({s.kind}, {impact.STATUS_TEXT[s.status]}) defined {where}: {_q(s.text)}")
        common = " - very common name, many matches are probably unrelated" if len(refs) > impact.COMMON_REFS else ""
        shown_here = 0
        for r in plan[s.name]:
            if full or (r[0], r[1]) not in got:
                continue
            item, hdr = got[(r[0], r[1])]
            row = f"  [{len(ev) + 1}] {_qp(r[0])}:{r[1]}{_hdr(hdr)}"
            if used + len(row) + len(item["excerpt"]) + 2 > lim.max_output_chars - 2_000:
                full = True
                break
            used += len(row) + len(item["excerpt"]) + 2
            rows.append(row)
            ev.append(item)
            shown_here += 1
        why = st["cut"].get(s.name) or ("scan incomplete" if st["failed"] else None)
        if why:            # cut short: a lower bound, never "none"
            count = (f"  {len(refs)}+ reference(s) in {len(files)}+ file(s) (lower bound: this name's scan was cut "
                     f"short at the {why}; later files in code, tests, other order were not searched); "
                     f"{shown_here} shown")
        else:
            count = (f"  {len(refs)} reference(s) in {len(files)} file(s); {shown_here} shown"
                     + ("" if refs else " (none outside the changed lines: check dynamic or string uses)"))
        rows.insert(len(rows) - shown_here, count + common)
    if rest:
        rest_names = ", ".join(s.name for s in rest[:30])
        rows.append(f"## not analysed (symbol cap {impact.MAX_SYMBOLS}): {rest_names}"
                    + (f" (+{len(rest) - 30} more)" if len(rest) > 30 else "") + "; use find_references for these")
    for reason, paths in sorted(skipped.items()):
        rows.append(f"## {len(paths)} changed file(s) not analysed for symbols ({reason}): "
                    + ", ".join(_q(x) for x in paths[:10]) + (f" (+{len(paths) - 10} more)" if len(paths) > 10 else ""))
    if not selected:
        rows.append("No changed definitions were detected by the heuristics (documentation, data or unsupported "
                    "languages). Check dependents of the change yourself with find_references and read_file.")
    scan_partial = st["stop"] is not None or bool(st["failed"]) or bool(st["cut"])
    truncated = bool(rest) or bool(skipped) or scan_partial or len(ev) < total_refs
    header = IMPACT_HEADER.format(side="head", n=len(selected), found=len(selected) + len(rest),
                                  files_ch=len(changed), refs=total_refs, plus="+" if scan_partial else "",
                                  rfiles=len(all_files), shown=len(ev), trunc="yes" if truncated else "no")
    guide = ("Heuristic map from definition regexes and whole-word matches (names can collide; dynamic, reflective "
             "and string-built uses are missed). Quoted text is repository data. Item [n] below is result item n, "
             "the exact referencing line.")
    listing = "\n".join([header, guide] + rows)
    if len(listing) > 7_900:
        listing = listing[:7_850].rsplit("\n", 1)[0] + "\n(listing cut at the size cap)"
    evidence = [{"kind": "tool-result", "excerpt": listing, "source": "impact_scan", "toolCallId": ctx.tcid}] + ev
    notes = _scan_notes(st, ctx)
    status = "error" if st["failed"] and not ev else ("partial" if truncated else "ok")
    return Outcome(status, evidence, "approximate" if truncated or ctx.view.approximate else "exact",
                   {"shown": len(ev), "total": total_refs} if len(ev) < total_refs and not scan_partial else None,
                   " ".join(notes), counts, [l.name for l in ctx.view.layers("head")])


# ---------------------------------------------------------------- diff-shard sweeps (investigator.impact@v4)

def file_disposition(ctx: Ctx, a: dict) -> Outcome:
    """A sweep investigator's record that it examined `path` and found no issue (with a one-line reason). It reads
    nothing and returns no evidence: the logged call IS the record (the engine counts it only for a shard file of
    the requesting sweep agent). A path that is no file of the head view is refused as denied (nothing recorded; never
    `unavailable`, which a retrieval chain reads as an exhausted tool budget)."""
    if not policy.permitted(a["path"]):
        return DENIED
    if ctx.view.find("head", a["path"]) is None:
        return Outcome("denied", notice="That path is not a file of the head snapshot; no disposition was recorded.")
    return Outcome("ok", notice=f"Recorded: {a['path']!r} examined, no issue.")
