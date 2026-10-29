"""Deterministic change-impact heuristics (host code, no model): which definitions a change touches, and the
enclosing definition of a referencing line.

This module lives outside `reviewer/tools` on purpose: the tool package stays free of regular expressions so that no
model-supplied text can ever become a pattern. The patterns here are fixed host constants applied to repository
text only (lines longer than MAX_DEF_LINE_CHARS are never matched, bounding backtracking). Whole-word reference
matching of a symbol is done regex-free in reviewer.tools.words.

Pure functions of (path, base lines, head lines). They are heuristics, deliberately conservative and bounded:

* A definition is found by a per-language line regex (Python, Go, JS/TS, Java; a generic `def|fn|func|class|...`
  pattern for other code; `key:` / `"key":` / `key =` for configuration files). Nothing is parsed or executed.
* A changed line (difflib opcode on either side) is attributed to the innermost definition that contains it, by
  indentation; a definition is "touched" when its own line or a line attributed to it changed. Blank and
  comment-only changed lines are ignored.
* Field names (dataclass / struct / interface / Java fields) are taken from changed lines inside a touched class,
  struct or interface; configuration keys from changed configuration lines.
* Guards against false positives: names shorter than 3 characters, keywords and very generic names, dunder
  methods, lines that look like comments, and every definition in a test file are skipped.

A reference is a whole-word occurrence of the name (reviewer.tools.words). Names can collide, and dynamic uses (reflection, string keys
built at runtime, re-exports under another name) are missed: the map is a starting point, never proof.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

IMPACT_VERSION = "impact-map@1"

# ---- bounds (also bound into the run config identity when impact mode is on)
MAX_CHANGED_FILES = 200          # changed files whose definitions are extracted
MAX_FILE_LINES = 20_000          # longer files are not analysed for definitions
MAX_DEFS_PER_FILE = 4_000
MAX_SYMBOLS = 20                 # symbols scanned for references
MAX_REFS_PER_SYMBOL_SHOWN = 6
MAX_REFS_SHOWN = 60
MAX_REF_LINE_CHARS = 300         # a longer reference line is counted, not shown
MAX_HEADER_CHARS = 160
MAX_DEF_LINE_CHARS = 1_000       # longer lines (minified code, data) are never matched as definitions
HEADER_LOOKBACK = 400            # lines searched upwards for an enclosing definition
COMMON_REFS = 200                # above this a name is flagged as probably colliding
SCAN_WALL_S = 25.0               # per impact scan (PREPARE's ceiling is 60 s)
LIMITS_DOC = {"version": IMPACT_VERSION, "maxChangedFiles": MAX_CHANGED_FILES, "maxFileLines": MAX_FILE_LINES,
              "maxDefsPerFile": MAX_DEFS_PER_FILE, "maxSymbols": MAX_SYMBOLS,
              "maxRefsPerSymbolShown": MAX_REFS_PER_SYMBOL_SHOWN, "maxRefsShown": MAX_REFS_SHOWN,
              "maxRefLineChars": MAX_REF_LINE_CHARS, "maxDefLineChars": MAX_DEF_LINE_CHARS,
              "headerLookback": HEADER_LOOKBACK, "commonRefs": COMMON_REFS, "scanWallS": SCAN_WALL_S}

ID = r"[A-Za-z_$][A-Za-z0-9_$]*"
SYMBOL_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:[.-][A-Za-z0-9_$]+)*")

# ---- languages by extension
_EXT = {}
for _l, _exts in (("python", ".py .pyi"), ("go", ".go"), ("js", ".js .jsx .mjs .cjs .ts .tsx .mts .cts"),
                  ("java", ".java"),
                  ("generic", ".rb .rs .c .h .cc .cpp .cxx .hpp .hh .cs .kt .kts .swift .php .scala .m .mm .ex .exs"),
                  ("config", ".yaml .yml .json .toml .ini .cfg .properties .conf")):
    for _e in _exts.split():
        _EXT[_e] = _l
CODE_LANGS = ("python", "go", "js", "java", "generic")


def language_of(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1].lower()
    dot = name.rfind(".")
    return None if dot <= 0 else _EXT.get(name[dot:])


_TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|specs|testdata|fixtures?)/|(?:^|/)test_[^/]*$|"
                        r"_test\.[a-z]+$|[._-](?:test|spec)\.[a-z]+$|Tests?\.java$|(?:^|/)conftest\.py$")


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


KEYWORDS = frozenset("""
and as assert async await break case catch class const continue debugger def default defer del delete do elif else
enum except export extends false final finally for from func function go goto if implements import in instanceof
interface is lambda let match new nil none not null of or package pass private protected public raise range return
select self static struct super switch this throw throws true try type typeof var void while with yield
""".split())
GENERIC_NAMES = frozenset("""
init main run get set put add new len str int map key keys val value values item items data name type id ids args
kwargs self cls this test tests setup teardown setUp tearDown constructor toString equals hashCode string error err
result results res req resp request response obj object list dict config options opts params param ctx context
call apply update create delete read write open close start stop next call handle handler callback cb fn func
default description title version enabled disabled true false none null path file files url size count index
port host user mode level kind tags labels image env
""".split())


def _good_name(name: str) -> bool:
    return (len(name) >= 3 and name.lower() not in KEYWORDS and name not in GENERIC_NAMES
            and not (name.startswith("__") and name.endswith("__")) and bool(SYMBOL_RE.fullmatch(name)))


# ---- definitions
@dataclass(frozen=True)
class Def:
    line: int            # 1-based
    name: str
    kind: str            # function | method | class | struct | interface | type | enum | constant | field | key
    indent: int
    text: str            # the definition line (stripped, bounded)


def _ind(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


_COMMENT = re.compile(r"\s*(?:#|//|/\*|\*|--|<!--|;)")

_PY = [(re.compile(rf"^(\s*)(?:async\s+)?def\s+({ID})\s*[\[(]"), "function"),
       (re.compile(rf"^(\s*)class\s+({ID})\b"), "class"),
       (re.compile(r"^()([A-Z][A-Z0-9_]{2,})\s*(?::[^=]*)?=(?!=)"), "constant")]
_GO = [(re.compile(rf"^()func\s+(?:\([^)]*\)\s*)?({ID})\s*[\[(]"), "function"),
       (re.compile(rf"^(\s*)type\s+({ID})\s+struct\b"), "struct"),
       (re.compile(rf"^(\s*)type\s+({ID})\s+interface\b"), "interface"),
       (re.compile(rf"^(\s*)type\s+({ID})\b"), "type"),
       (re.compile(r"^()(?:const|var)\s+([A-Z]\w*)\b"), "constant")]
_JS_KW = r"(?:export\s+)?(?:default\s+)?(?:declare\s+)?"
_JS = [(re.compile(rf"^(\s*){_JS_KW}(?:async\s+)?function\s*\*?\s*({ID})\s*[<(]"), "function"),
       (re.compile(rf"^(\s*){_JS_KW}(?:abstract\s+)?class\s+({ID})"), "class"),
       (re.compile(rf"^(\s*){_JS_KW}interface\s+({ID})"), "interface"),
       (re.compile(rf"^(\s*){_JS_KW}type\s+({ID})\s*(?:<[^=]*>)?\s*="), "type"),
       (re.compile(rf"^(\s*){_JS_KW}(?:const\s+)?enum\s+({ID})"), "enum"),
       (re.compile(rf"^()(?:export\s+)?(?:const|let|var)\s+({ID})\s*(?::[^=]+)?=\s*(?:async\s+)?"
                   rf"(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|{ID}\s*=>)"), "function"),
       (re.compile(rf"^()export\s+(?:const|let|var)\s+({ID})"), "constant"),
       (re.compile(rf"^(\s+)(?:(?:public|private|protected|static|readonly|async|override|abstract|get|set)\s+)*"
                   rf"({ID})\s*(?:<[^>]*>)?\s*\([^;]*\)\s*(?::\s*[^={{;]+)?\{{\s*$"), "method")]
_JAVA_MOD = r"(?:(?:public|protected|private|static|final|abstract|sealed|non-sealed|strictfp|synchronized|native|default)\s+)*"
_JAVA = [(re.compile(rf"^(\s*){_JAVA_MOD}(?:class|interface|enum|record|@interface)\s+({ID})"), "class"),
         (re.compile(rf"^(\s*)(?:(?:public|protected|private)\s+)?static\s+final\s+[\w.<>\[\], ?]+\s+({ID})\s*="),
          "constant"),
         (re.compile(rf"^(\s*){_JAVA_MOD}(?:<[^>]+>\s+)?[\w.$<>\[\]?]+(?:<[^()]*>)?(?:\[\])*\s+({ID})\s*\([^;]*$"),
          "method")]
_GENERIC = [(re.compile(rf"^(\s*)(?:(?:pub(?:\([^)]*\))?|export|public|private|protected|internal|static|async|"
                        rf"unsafe|extern|inline|override|open|final|abstract|suspend|data|sealed)\s+)*"
                        rf"(def|fn|func|function|fun|class|struct|interface|trait|enum|module|protocol|object|union)"
                        rf"\s+({ID})"), "generic")]
_CONFIG = [re.compile(r"""^(\s*)-?\s*["']?([A-Za-z_][\w.-]*)["']?\s*:(?:\s|$)"""),
           re.compile(r"""^(\s*)"([A-Za-z_][\w.-]*)"\s*:"""),
           re.compile(r"""^(\s*)([A-Za-z_][\w.-]*)\s*=(?!=)""")]
_GENERIC_KIND = {"def": "function", "fn": "function", "func": "function", "function": "function", "fun": "function",
                 "class": "class", "struct": "struct", "interface": "interface", "trait": "interface",
                 "protocol": "interface", "enum": "enum", "module": "class", "object": "class", "union": "struct"}
_FIRST_WORD_NOT_DEF = frozenset("return new throw else case yield await if for while switch catch do try assert "
                                "goto break continue delete typeof import package".split())
CONTAINERS = ("class", "struct", "interface", "type", "enum")

_FIELD = {"python": re.compile(rf"^\s+({ID})\s*:\s*[^=\s]"),
          "go": re.compile(r"^\s+([A-Z]\w*)\s+[\w.*\[\]{}]"),
          "js": re.compile(rf"^\s+(?:readonly\s+)?({ID})\??\s*:"),
          "java": re.compile(rf"^\s+(?:(?:public|protected|private|final|static|transient|volatile)\s+)+"
                             rf"[\w.<>\[\], ?]+\s+({ID})\s*(?:=|;)")}


def def_on_line(lang: str | None, line: str) -> tuple[str, str] | None:
    """(name, kind) of the definition this one line starts, or None. Comments never define anything."""
    if lang is None or lang == "config" or len(line) > MAX_DEF_LINE_CHARS or _COMMENT.match(line):
        return None
    if lang in ("java", "js"):
        first = line.lstrip().split(" ", 1)[0].split("(", 1)[0]
        if first in _FIRST_WORD_NOT_DEF:
            return None
    pats = {"python": _PY, "go": _GO, "js": _JS, "java": _JAVA, "generic": _GENERIC}[lang]
    for rx, kind in pats:
        m = rx.match(line)
        if m is None:
            continue
        if kind == "generic":
            return m.group(3), _GENERIC_KIND[m.group(2)]
        name = m.group(2)
        if name in KEYWORDS:
            continue
        if kind == "function" and lang == "python" and m.group(1):
            kind = "method"
        return name, kind
    return None


def definitions(path: str, lines: list[str]) -> list[Def]:
    lang = language_of(path)
    if lang not in CODE_LANGS or len(lines) > MAX_FILE_LINES:
        return []
    out, block = [], None
    for n, ln in enumerate(lines, 1):
        if lang == "go":                              # `const (` / `var (` blocks: exported names inside
            s = ln.strip()
            if block is None and re.match(r"^(const|var)\s*\($", s):
                block = n
                continue
            if block is not None:
                if s.startswith(")"):
                    block = None
                else:
                    m = re.match(r"^\s+([A-Z]\w*)\b", ln)
                    if m and _good_name(m.group(1)):
                        out.append(Def(n, m.group(1), "constant", _ind(ln), ln.strip()[:MAX_HEADER_CHARS]))
                continue
        d = def_on_line(lang, ln)
        if d is not None:
            out.append(Def(n, d[0], d[1], _ind(ln), ln.strip()[:MAX_HEADER_CHARS]))
            if len(out) >= MAX_DEFS_PER_FILE:
                break
    return out


def _regions(defs: list[Def], n_lines: int) -> list[tuple[Def, int]]:
    """(def, last line) where a definition extends until the next definition at the same or a lower indent.
    Constants occupy their own line only."""
    out = []
    for i, d in enumerate(defs):
        if d.kind == "constant":
            out.append((d, d.line))
            continue
        end = n_lines
        for e in defs[i + 1:]:
            if e.indent <= d.indent:
                end = e.line - 1
                break
        out.append((d, max(d.line, end)))
    return out


def innermost(regions: list[tuple[Def, int]], line: int) -> Def | None:
    best = None
    for d, end in regions:
        if d.line <= line <= end and (best is None or d.line >= best.line):
            best = d
    return best


def changed_lines(base: list[str], head: list[str]) -> tuple[set, set]:
    """(base line numbers removed or replaced, head line numbers added or replaced), 1-based."""
    sm = difflib.SequenceMatcher(None, base, head, autojunk=False)
    b, h = set(), set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            b.update(range(i1 + 1, i2 + 1))
            h.update(range(j1 + 1, j2 + 1))
    return b, h


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    status: str          # removed | signature | body | field | key | added
    path: str
    line: int            # definition line on `side`
    side: str            # head | base (removed symbols)
    text: str


STATUS_ORDER = {"removed": 0, "signature": 1, "body": 2, "field": 3, "key": 4, "added": 5}
STATUS_TEXT = {"removed": "removed", "signature": "definition line changed", "body": "body changed",
               "field": "field changed", "key": "config key changed", "added": "added"}


def _touched(defs: list[Def], lines: list[str], changed: set) -> dict:
    """{def: [changed lines attributed to it]} for every definition touched by the changed lines. Blank and
    comment-only changed lines touch nothing (a reflow or comment edit is not a contract change)."""
    regions = _regions(defs, len(lines))
    out: dict = {}
    for ln in sorted(changed):
        text = lines[ln - 1] if ln <= len(lines) else ""
        if not text.strip() or _COMMENT.match(text):
            continue
        d = innermost(regions, ln)
        if d is not None:
            out.setdefault(d, []).append(ln)
    return out


def _fields(lang: str, lines: list[str], touched: dict, path: str) -> list[Symbol]:
    rx = _FIELD.get(lang)
    out = []
    if rx is None:
        return out
    for d, lns in touched.items():
        if d.kind not in CONTAINERS:
            continue
        for ln in lns:
            text = lines[ln - 1]
            if ln == d.line or len(text) > MAX_DEF_LINE_CHARS or _COMMENT.match(text) or def_on_line(lang, text):
                continue
            m = rx.match(text)
            if m and _good_name(m.group(1)) and len(m.group(1)) >= 4:
                out.append(Symbol(m.group(1), "field", "field", path, ln, "head", text.strip()[:MAX_HEADER_CHARS]))
    return out


def _config_keys(path: str, lines: list[str], changed: set, side: str) -> list[Symbol]:
    out = []
    for ln in sorted(changed):
        if ln > len(lines):
            continue
        text = lines[ln - 1]
        if len(text) > MAX_DEF_LINE_CHARS or _COMMENT.match(text) and not text.lstrip().startswith("-"):
            continue
        for rx in _CONFIG:
            m = rx.match(text)
            if m:
                key = m.group(2)
                if _good_name(key) and len(key) >= 4:
                    out.append(Symbol(key, "key", "key", path, ln, side, text.strip()[:MAX_HEADER_CHARS]))
                break
    return out


def file_symbols(path: str, base: list[str] | None, head: list[str] | None) -> tuple[list[Symbol], set]:
    """(symbols this file's change touches, head line numbers that changed). `base`/`head` None = absent side
    (added or deleted file). Test files contribute no symbols (their definitions have no dependents worth a scan)."""
    b_lines, h_lines = base or [], head or []
    if len(b_lines) > MAX_FILE_LINES or len(h_lines) > MAX_FILE_LINES:
        return [], set()
    bc, hc = changed_lines(b_lines, h_lines)
    lang = language_of(path)
    if lang is None or is_test_path(path):
        return [], hc
    if lang == "config":
        keys = _config_keys(path, h_lines, hc, "head")
        have = {k.name for k in keys}
        keys += [s for s in _config_keys(path, b_lines, bc, "base") if s.name not in have]
        return keys, hc
    hdefs, bdefs = definitions(path, h_lines), definitions(path, b_lines)
    hnames, bnames = {d.name for d in hdefs}, {d.name for d in bdefs}
    out: list[Symbol] = []
    touched_h = _touched(hdefs, h_lines, hc)
    for d, _ in sorted(touched_h.items(), key=lambda kv: kv[0].line):
        if not _good_name(d.name):
            continue
        status = "added" if d.name not in bnames else ("signature" if d.line in hc else "body")
        out.append(Symbol(d.name, d.kind, status, path, d.line, "head", d.text))
    out += _fields(lang, h_lines, touched_h, path)
    for d, _ in sorted(_touched(bdefs, b_lines, bc).items(), key=lambda kv: kv[0].line):
        if d.name not in hnames and _good_name(d.name):
            out.append(Symbol(d.name, d.kind, "removed", path, d.line, "base", d.text))
    return out, hc


def select(symbols: list[Symbol], cap: int = MAX_SYMBOLS) -> tuple[list[Symbol], list[Symbol]]:
    """One entry per name (its most important change), ordered removed > signature > body > field > key > added,
    then path and line. -> (selected, not selected)."""
    best: dict[str, Symbol] = {}
    for s in symbols:
        cur = best.get(s.name)
        if cur is None or (STATUS_ORDER[s.status], s.path, s.line) < (STATUS_ORDER[cur.status], cur.path, cur.line):
            best[s.name] = s
    ordered = sorted(best.values(), key=lambda s: (STATUS_ORDER[s.status], s.path, s.line, s.name))
    return ordered[:cap], ordered[cap:]


# ---- references
def enclosing_header(path: str, lines: list[str], n: int) -> tuple[int, str] | None:
    """(line, text) of the nearest definition above line n whose indent is smaller than line n's (or the
    definition on line n itself), searched at most HEADER_LOOKBACK lines up."""
    lang = language_of(path)
    if lang not in CODE_LANGS:
        return None
    here = lines[n - 1]
    d = def_on_line(lang, here)
    if d is not None:
        return n, here.strip()[:MAX_HEADER_CHARS]
    ind = _ind(here)
    for k in range(n - 1, max(0, n - 1 - HEADER_LOOKBACK), -1):
        t = lines[k - 1]
        if t.strip() and _ind(t) < ind and def_on_line(lang, t) is not None:
            return k, t.strip()[:MAX_HEADER_CHARS]
    return None


def ref_sort_key(path: str, line: int) -> tuple:
    """Production code first, then tests, then everything else (docs, data)."""
    lang = language_of(path)
    group = 2 if lang not in CODE_LANGS else (1 if is_test_path(path) else 0)
    return group, path, line
