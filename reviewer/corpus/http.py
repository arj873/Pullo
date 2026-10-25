"""Public anonymous GET client with an explicit host/repo/ref allowlist and hard limits.

No credentials are read or sent. Every ref is a 40-hex commit sha, so a branch name
(today's main) can never be requested. Redirects are refused.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

ALLOWED_HOSTS = ("api.github.com", "raw.githubusercontent.com")
ALLOWED_REPOS = ("boykopovar/AnyPS5", "stablyai/orca", "Vencord/Vesktop")
USER_AGENT = "reviewer-corpus-r01/1 (read-only historical import)"
SHA = r"[0-9a-f]{40}"
_NAME = r"[A-Za-z0-9._-]{1,100}"
_API = re.compile(rf"^/repos/({_NAME})/({_NAME})/(pulls/\d{{1,9}}(?:/files)?|compare/{SHA}\.\.\.{SHA})$")


@dataclass(frozen=True)
class Limits:
    timeout: float = 20.0          # per socket operation
    request_deadline: float = 40.0  # wall time per request
    api_bytes: int = 12 << 20
    file_bytes: int = 1 << 20      # per fetched file or patch
    case_bytes: int = 16 << 20     # raw bytes fetched per case
    max_files: int = 300           # changed files kept per case
    max_pages: int = 30
    max_requests: int = 400
    max_total_bytes: int = 128 << 20
    max_context_files: int = 50


class FetchError(Exception):
    def __init__(self, kind: str, message: str = "", status: int | None = None):
        super().__init__(f"{kind}: {message}" if message else kind)
        self.kind, self.status = kind, status


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict
    body: bytes


def check_url(url: str, allowed_repos=ALLOWED_REPOS, scope: dict | None = None) -> tuple[str, str]:
    """Return (kind, 'owner/repo') or raise FetchError('policy').

    `scope` ({"repo", "pr" (int|None), "shas" (set)}) narrows the allowlist to one case:
    only that PR number and those commit shas; pr=None denies the API entirely."""
    def deny(why):
        raise FetchError("policy", f"{why}: {url[:120]}")
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS or u.username or u.password \
            or u.port is not None or u.fragment or (u.netloc != u.hostname):
        deny("scheme/host not allowed")
    allowed = {r.lower() for r in allowed_repos}
    if u.hostname == "api.github.com":
        m = _API.match(u.path)
        if not m:
            deny("api path not allowed")
        repo = f"{m.group(1)}/{m.group(2)}"
        what = m.group(3)
        q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        if q and (not (u.path.endswith("/files") or "/compare/" in u.path)
                  or any(k not in ("per_page", "page") or not v.isdigit() or len(v) > 4 for k, v in q)):
            deny("query not allowed")
        kind = "api"
        refs = re.findall(SHA, what)
        pr = int(what.split("/")[1]) if what.startswith("pulls/") else None
    else:
        if u.query:
            deny("query not allowed")
        parts = u.path.split("/")
        if len(parts) < 5 or parts[0] != "" or not re.fullmatch(_NAME, parts[1]) \
                or not re.fullmatch(_NAME, parts[2]) or not re.fullmatch(SHA, parts[3]):
            deny("raw path needs owner/repo/<40-hex sha>/path")
        for seg in parts[4:]:
            d = urllib.parse.unquote(seg)
            if d in ("", ".", "..") or "/" in d or "\\" in d or any(ord(c) < 32 for c in d):
                deny("unsafe path segment")
        repo = f"{parts[1]}/{parts[2]}"
        kind, refs, pr = "raw", [parts[3]], None
    if repo.lower() not in allowed:
        deny("repository not allowlisted")
    if scope is not None:
        if repo.lower() != scope["repo"].lower():
            deny("outside the case repository")
        if kind == "api" and (scope["pr"] is None or (pr is not None and pr != scope["pr"])):
            deny("outside the case pull request")
        if any(r not in scope["shas"] for r in refs):
            deny("commit is not pinned for this case")
    return kind, repo


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def proxy_configured(url: str) -> bool:
    """True if the environment names a proxy for this URL (credentials in it are never read)."""
    u = urllib.parse.urlsplit(url)
    px = urllib.request.getproxies()
    return bool(px.get(u.scheme) or px.get("all")) and not urllib.request.proxy_bypass(u.hostname or "")


def _loopback(host: str | None) -> bool:
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


def _tracked(base, st):
    """Connection class that hands its socket to the caller, so the deadline can cut a read that
    is stuck anywhere (header trickle included), and refuses to connect once the deadline passed."""
    class Conn(base):
        def connect(self):
            if st.get("expired"):
                raise TimeoutError("request deadline exceeded before connect")
            super().connect()
            st["sock"] = self.sock
            if st.get("expired"):
                self.sock.close()
                raise TimeoutError("request deadline exceeded while connecting")
    return Conn


def _opener(st):
    plain, secure = _tracked(http.client.HTTPConnection, st), _tracked(http.client.HTTPSConnection, st)

    class Http(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(plain, req)

    class Https(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(secure, req, context=self._context)

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect, Http, Https)


def _fetch(url, headers, timeout, max_bytes, deadline, st) -> Response:
    req = urllib.request.Request(url, headers=headers, method="GET")
    opener = _opener(st)
    try:
        resp = opener.open(req, timeout=max(0.05, min(timeout, deadline - time.monotonic())))
        status, hdrs = resp.status, resp.headers
    except urllib.error.HTTPError as e:
        resp, status, hdrs = e, e.code, e.headers
        max_bytes = min(max_bytes, 65536)
    st["resp"] = resp
    with resp:
        cl = hdrs.get("content-length")
        if cl and cl.isdigit() and int(cl) > max_bytes and status == 200:
            raise FetchError("too-large", f"content-length {cl} > {max_bytes}")
        chunks, n = [], 0
        read = getattr(resp, "read1", resp.read)
        while True:
            if time.monotonic() > deadline:
                raise FetchError("timeout", "request deadline exceeded")
            c = read(8192)
            if not c:
                break
            n += len(c)
            st["bytes"] = st.get("bytes", 0) + len(c)
            if n > max_bytes:
                if status != 200:
                    break
                raise FetchError("too-large", f"body exceeds {max_bytes}")
            chunks.append(c)
    return Response(status, {k.lower(): v for k, v in hdrs.items()}, b"".join(chunks))


def urllib_transport(url, headers, timeout, max_bytes, deadline) -> Response:
    """One GET with a hard wall-clock deadline (DNS, connect and slow-drip reads included).

    The work runs in a daemon thread that the caller stops waiting for at `deadline`.
    Proxies are unsupported: if the environment configures one for this URL the request is
    refused rather than bypassing it or sending anything through it."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" and not (u.scheme == "http" and _loopback(u.hostname)):
        raise FetchError("policy", f"transport speaks https only (http to a loopback address for tests): {url[:80]}")
    if proxy_configured(url):
        raise FetchError("proxy-configured", "an environment proxy applies to this URL; proxies are "
                         "unsupported, refusing to bypass or use it (unset it or allow direct access)")
    box: dict = {}
    st: dict = {}

    def work():
        try:
            box["r"] = _fetch(url, headers, timeout, max_bytes, deadline, st)
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller
            box["e"] = e

    th = threading.Thread(target=work, daemon=True, name="corpus-http")
    th.start()
    th.join(max(0.0, deadline - time.monotonic()))
    if th.is_alive():
        st["expired"] = True
        sock = st.get("sock")
        if sock is not None:
            try:  # wakes a worker blocked in recv, whatever phase it is in
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        raise _spent(FetchError("timeout", "wall-clock request deadline exceeded"), st)
    if "e" in box:
        e = box["e"]
        if isinstance(e, urllib.error.URLError) and isinstance(e.reason, TimeoutError):
            e = FetchError("timeout", str(e.reason))
        raise _spent(e, st)
    return box["r"]


def _spent(e: BaseException, st: dict) -> BaseException:
    """Record the body bytes consumed before a failure, so the caller's budget counts them."""
    try:
        e.bytes_read = st.get("bytes", 0)
    except Exception:  # noqa: BLE001
        pass
    return e


class Client:
    def __init__(self, transport=None, limits: Limits = Limits(), allowed_repos=ALLOWED_REPOS, log=None):
        self.transport = transport or urllib_transport
        self.limits, self.allowed_repos = limits, allowed_repos
        self.log = log or (lambda m: None)
        self.scope: dict | None = None
        self.requests: list[dict] = []
        self.total_bytes = 0
        self.rate_limited = False

    def set_scope(self, repo: str, pr: int | None, shas) -> None:
        self.scope = {"repo": repo, "pr": pr, "shas": set(shas)}

    def pin_sha(self, sha: str) -> None:
        self.scope["shas"].add(sha)

    def get(self, url: str, *, max_bytes: int | None = None) -> Response:
        rec = {"url": url, "status": None, "error": None}
        self.requests.append(rec)
        try:
            check_url(url, self.allowed_repos, self.scope)
            if self.rate_limited:
                raise FetchError("rate-limit", "earlier request was rate limited; not retrying")
            if len(self.requests) > self.limits.max_requests:
                raise FetchError("budget", f"request limit {self.limits.max_requests}")
            if self.total_bytes >= self.limits.max_total_bytes:
                raise FetchError("budget", "total byte limit")
            cap = max_bytes if max_bytes is not None else self.limits.api_bytes
            headers = {"Accept": "application/vnd.github+json" if "api." in url else "*/*",
                       "User-Agent": USER_AGENT}
            try:
                r = self.transport(url, headers, self.limits.timeout, cap,
                                   time.monotonic() + self.limits.request_deadline)
            except FetchError as e:
                self.total_bytes += getattr(e, "bytes_read", 0)
                raise
            except TimeoutError as e:
                self.total_bytes += getattr(e, "bytes_read", 0)
                raise FetchError("timeout", str(e)) from e
            except OSError as e:
                self.total_bytes += getattr(e, "bytes_read", 0)
                raise FetchError("network", f"{type(e).__name__}: {e}") from e
            rec["status"] = r.status
            self.total_bytes += len(r.body)
            if r.status == 200:
                if len(r.body) > cap:
                    raise FetchError("too-large", f"body {len(r.body)} > {cap}", 200)
                return r
            if 300 <= r.status < 400:
                raise FetchError("redirect", "redirects are refused", r.status)
            if r.status == 429 or (r.status == 403 and r.headers.get("x-ratelimit-remaining") == "0"):
                self.rate_limited = True
                raise FetchError("rate-limit", f"HTTP {r.status}", r.status)
            if r.status == 404:
                raise FetchError("not-found", "HTTP 404", 404)
            raise FetchError("http", f"HTTP {r.status}", r.status)
        except FetchError as e:
            rec["error"] = e.kind
            self.log(f"GET {url} -> {e}")
            raise
