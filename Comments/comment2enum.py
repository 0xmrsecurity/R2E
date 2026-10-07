#!/usr/bin/env python3
"""comment2enum - extract and triage hidden HTML comments from web targets.

Part of the ad2enum enumeration toolkit, for authorized security testing
only (bug bounty recon, pentests, labs).

v3 rewrite. What changed versus v2 and why:
- Retries with exponential backoff + full jitter, honoring Retry-After.
  v2 had none: a single 429/502 from a WAF or flaky CDN lost the target.
- Proxy support (--proxy or standard HTTP(S)_PROXY env) so traffic can go
  through Burp/Caido/ZAP for verification.
- TLS verification ON by default; --insecure opts out. v2 forced
  verify=False globally and silenced the warnings.
- Response body size cap (--max-size) bounds memory on hostile pages.
- URL normalization + validation: bare hostnames get https://, junk is
  skipped with a warning instead of raising MissingSchema per target.
- HTTP status is recorded; 4xx/5xx are failures, not "ok with 0 comments".
- Thread-local sessions: requests.Session is not documented as safe to
  share across concurrently submitting threads.
- One broken target can never kill the run: every future's result is
  collected inside a try/except. v2 let any unexpected exception tear
  down the whole as_completed loop and lose all results.
- Structured logging (stderr), JSON + text reports in a timestamped
  output directory, meaningful exit codes, type hints, unit tests.
- Keyword triage: comments containing credentials, TODO/FIXME, internal
  IPs, emails, URLs or unix paths are flagged in the report.

v3.1 hardening. What changed versus v3.0 and why:
- Body downloads go through requests' public iter_content() instead of the
  semi-private resp.raw.read(). Raw reads raise *unwrapped* urllib3 errors
  (ProtocolError, ReadTimeoutError) that are not requests.RequestException,
  so a connection drop mid-download bypassed the retry loop entirely and
  was reported as a permanent "internal" scanner error. iter_content also
  applies content-decoding and re-raises those failures as requests
  exceptions our retry policy already understands.
- Content-Type gate: binary bodies (PDF, images, archives) are no longer
  fed to BeautifulSoup - wasted CPU and false triage hits from random byte
  sequences. A missing header still parses (false negatives are worse than
  a size-capped wasted parse); --parse-all disables the gate.
- Retry-After is honored but capped by --max-wait (default 60s): a buggy
  or hostile server answering "Retry-After: 86400" could previously park a
  worker for a full day.
- Global --rps token-bucket throttle: the v3.0 --delay only paused each
  target's *first* request, so nothing stopped a large list from bursting
  hundreds of requests/second at a shared CDN/WAF.
- -H/--header and --cookie enable authenticated scanning; names and values
  are validated (RFC 7230 token, no CR/LF) so config cannot smuggle an
  extra request line onto the wire.
- JSON --config file and COMMENT2ENUM_* env vars, precedence
  CLI > env > config file > built-in defaults.
- Missing beautifulsoup4 now exits cleanly with code 3 (like requests)
  instead of an ImportError traceback.
- Thread-local sessions are registered and closed after the run; [i/n]
  progress on every completed target; a second Ctrl+C while the pool drains
  in-flight scans still writes partial results.
- Reports gain final_url, content_type and truncated fields plus a skipped
  counter; usage errors exit 1 (argparse's default exit 2 collided with
  "the scan ran but targets failed").
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from threading import Lock, local
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import urlparse, urlunparse

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write("missing dependency 'requests': pip install -r requirements.txt\n")
    raise SystemExit(3)

try:
    import urllib3
except ImportError:  # pragma: no cover
    urllib3 = None

try:
    from bs4 import BeautifulSoup, Comment
except ImportError:  # pragma: no cover - environment dependent
    # Graceful degradation like the requests guard above: a missing parser
    # dependency is a setup problem, not a crash with a traceback.
    sys.stderr.write("missing dependency 'beautifulsoup4': pip install -r requirements.txt\n")
    raise SystemExit(3)

log = logging.getLogger("comment2enum")

VERSION = "3.1.0"

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Transient / throttling statuses worth another attempt. 4xx other than
# these are deterministic client-side answers; retrying wastes quota.
RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504, 522, 524})

# Triage patterns applied to each extracted comment. Kept intentionally
# broad: comments are few, false positives cost nothing here (unlike the
# git-diff grep in gitcheck2enum.sh, where volume made bare words useless).
INTERESTING_PATTERNS: dict[str, re.Pattern[str]] = {
    "credential": re.compile(
        r"(password|passwd|pwd|secret|api[_-]?key|apikey|token|auth"
        r"|access[_-]?key|private[_-]?key|client[_-]?secret)",
        re.IGNORECASE,
    ),
    "todo": re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|DEPRECATED|TEMP)\b"),
    "internal-ip": re.compile(
        r"\b(10(\.\d{1,3}){3}|192\.168(\.\d{1,3}){2}"
        r"|172\.(1[6-9]|2\d|3[01])(\.\d{1,3}){2})\b"
    ),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "url": re.compile(r"""https?://[^\s"'<>]+"""),
    "debug": re.compile(
        r"\b(debug|staging|dev-only|localhost|internal|do not (delete|remove|edit))\b",
        re.IGNORECASE,
    ),
    "unix-path": re.compile(r"/(?:etc|home|var|opt|usr|proc|srv|tmp)/"),
}


@dataclass
class ScanConfig:
    timeout: float = 15.0
    retries: int = 3
    backoff: float = 1.0          # base seconds for exponential backoff
    max_backoff: float = 30.0     # ceiling per single computed wait
    max_wait: float = 60.0        # ceiling for a server-supplied Retry-After
    delay: float = 0.0            # polite pause before each target's first attempt
    max_bytes: int = 2_000_000    # response body cap
    verify_tls: bool = True
    proxy: str | None = None
    user_agent: str = DEFAULT_UA
    follow_redirects: bool = True
    workers: int = 5
    rps: float | None = None      # global request-start cap; None = unlimited
    headers: dict[str, str] = field(default_factory=dict)  # extra request headers
    cookie: str | None = None     # Cookie header for authenticated scans
    parse_all: bool = False       # disable the Content-Type skip gate


@dataclass
class ScanResult:
    url: str
    status: str                            # "ok" | "skip" | "fail"
    http_status: int | None = None
    final_url: str | None = None           # URL after redirects
    content_type: str | None = None
    truncated: bool = False                # body hit the --max-size cap
    comments: list[str] = field(default_factory=list)
    interesting: list[dict] = field(default_factory=list)
    error: str | None = None               # failure reason, or skip reason when status == "skip"
    attempts: int = 0
    elapsed: float = 0.0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "http_status": self.http_status,
            "final_url": self.final_url,
            "content_type": self.content_type,
            "truncated": self.truncated,
            "comment_count": len(self.comments),
            "comments": self.comments,
            "interesting": self.interesting,
            "error": self.error,
            "attempts": self.attempts,
            "elapsed_sec": round(self.elapsed, 2),
        }


# --------------------------------------------------------------------------
# Pure helpers (unit-tested, no network)
# --------------------------------------------------------------------------

# A leading "scheme:" token. Checked BEFORE prepending https://: the old
# '"://" not in candidate' test missed schemes that take no authority, so
# "javascript:alert(1)" became "https://javascript:alert(1)" and parsed as a
# valid host named "javascript".
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


def normalize_url(raw: str) -> str | None:
    """Return an absolute http(s) URL, or None when the input is unusable.

    Bare hostnames get an https:// scheme; pass http:// explicitly for
    plaintext targets. Rejects non-http schemes and malformed hosts so a
    typo cannot produce per-target MissingSchema noise.
    """
    candidate = (raw or "").strip()
    if not candidate:
        return None
    if _SCHEME_RE.match(candidate):
        if urlparse(candidate).scheme.lower() not in ("http", "https"):
            return None
    else:
        candidate = "https://" + candidate
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname
        port = parsed.port  # raises ValueError when the port is not numeric
    except ValueError:
        return None
    if not host:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    if ":" in host:  # IPv6 literal
        if not re.fullmatch(r"[0-9A-Fa-f:]+", host):
            return None
    elif not re.fullmatch(r"[A-Za-z0-9._~-]+", host):
        return None
    if parsed.fragment:
        # Fragments are never sent to the server; dropping them stops
        # "page#a" and "page#b" from scanning the same resource twice.
        candidate = urlunparse(parsed._replace(fragment=""))
    return candidate


def dedup_key(url: str) -> str:
    """Canonical identity of a normalized URL, used for de-duplication.

    Hosts are case-insensitive, an empty path and "/" name the same
    resource, default ports are implicit and fragments are client-side
    only - so "https://A.test", "https://a.test:443/" and
    "https://a.test/#top" must collapse to one target, not three.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port  # raises ValueError on a malformed port
    except ValueError:
        return url  # keep something stable rather than crashing on junk
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    port_part = f":{port}" if port is not None and port != default_port else ""
    host_part = f"[{host}]" if ":" in host else host
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{host_part}{port_part}{path}{query}"


def compute_backoff(attempt: int, base: float, cap: float) -> float:
    """Exponential backoff with full jitter (AWS-style). attempt is 0-based."""
    ceiling = min(cap, base * (2 ** attempt))
    return random.uniform(0.0, ceiling)


def should_parse_content_type(content_type: str | None) -> bool:
    """True when a body with this Content-Type is worth HTML parsing.

    The gate skips obvious binaries (PDF, images, archives, fonts) that
    would waste CPU in BeautifulSoup and could produce garbage triage hits
    from random byte sequences. A missing/empty header parses anyway:
    plenty of small servers omit Content-Type on real HTML pages, and a
    false negative costs more than a wasted parse of a size-capped body.
    """
    if not content_type:
        return True
    essence = content_type.split(";", 1)[0].strip().lower()
    if not essence:
        return True
    return essence.startswith("text/") or any(
        hint in essence for hint in ("html", "xml", "svg", "json")
    )


# RFC 7230 token characters - no separators, no whitespace, no CTLs.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def parse_header(raw: str) -> tuple[str, str]:
    """Split one "Name: value" header, rejecting request-smuggling input.

    Raises ValueError with a human-readable message so the CLI can report a
    clean usage error. CR/LF are rejected outright: values reach the wire
    verbatim, so a newline here (from a config file or wrapper script) would
    inject a second request line.
    """
    if "\r" in raw or "\n" in raw:
        raise ValueError(f"header must not contain CR/LF: {raw!r}")
    name, sep, value = raw.partition(":")
    name = name.strip()
    if not sep or not name:
        raise ValueError(f"expected 'Name: value', got {raw!r}")
    if not _HEADER_NAME_RE.match(name):
        raise ValueError(f"invalid header name {name!r}")
    return name, value.strip()


def validate_cookie(raw: str) -> str:
    """Reject a Cookie value containing CR/LF (header injection); return it."""
    if "\r" in raw or "\n" in raw:
        raise ValueError("--cookie must not contain CR/LF")
    return raw


class RateLimiter:
    """Global token bucket capping request starts per second across workers.

    The per-target --delay only pauses each target's *first* request, so a
    large list could still burst hundreds of requests/second at a shared
    CDN/WAF. This spaces request *starts* (not sleeps), keeping the offered
    rate at `rps` even when some targets are slow; the lock is held only to
    reserve a slot, so one slow target never blocks unrelated workers.
    """

    def __init__(self, rps: float | None) -> None:
        self._interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._lock = Lock()
        self._next_slot = 0.0

    def wait(self) -> None:
        if self._interval <= 0.0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self._interval
        pause = slot - now
        if pause > 0:
            time.sleep(pause)


def retry_after_seconds(response) -> float | None:
    """Parse a Retry-After header (delta-seconds or HTTP-date), else None."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def make_soup(content: bytes) -> BeautifulSoup:
    """Parse with lxml when available, silently fall back to stdlib."""
    for parser in ("lxml", "html.parser"):
        try:
            return BeautifulSoup(content, parser)
        except Exception:  # FeatureNotFound and friends
            continue
    raise RuntimeError("no usable HTML parser; pip install beautifulsoup4 lxml")


def extract_comments(soup: BeautifulSoup) -> list[str]:
    out: list[str] = []
    for node in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(node).strip()
        if text:
            out.append(text)
    return out


def triage_comments(comments: Iterable[str]) -> list[dict]:
    """Flag comments matching interesting patterns, with a bounded snippet."""
    hits: list[dict] = []
    for idx, comment in enumerate(comments, 1):
        labels = sorted(name for name, pat in INTERESTING_PATTERNS.items() if pat.search(comment))
        if labels:
            snippet = comment if len(comment) <= 300 else comment[:300] + "..."
            hits.append({"index": idx, "labels": labels, "text": snippet})
    return hits


# --------------------------------------------------------------------------
# HTTP scanning
# --------------------------------------------------------------------------

class HttpClient:
    """Per-thread requests.Session, manual retry policy (no urllib3 Retry).

    Retries are handled here rather than via HTTPAdapter(max_retries=...)
    because we need to honor (capped) Retry-After, apply the global rate
    limit, and distinguish retryable status codes from retryable
    exceptions with logging.

    Thread-safety: requests.Session is not documented as safe to share
    across concurrently submitting threads, so each worker builds its own
    in a thread-local; every created session is registered under a lock so
    close() can release its sockets once the pool has drained.
    """

    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self._tls = local()
        self._sessions_lock = Lock()
        self._sessions: list[requests.Session] = []
        self.rate_limiter = RateLimiter(cfg.rps)

    def _session(self) -> requests.Session:
        session = getattr(self._tls, "session", None)
        if session is None:
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            session.headers.update({"User-Agent": self.cfg.user_agent, "Accept": "*/*"})
            if self.cfg.headers:
                # Applied after the defaults so -H can override them.
                session.headers.update(self.cfg.headers)
            if self.cfg.cookie:
                # setdefault: an explicit -H "Cookie: ..." wins over --cookie.
                session.headers.setdefault("Cookie", self.cfg.cookie)
            if self.cfg.proxy:
                # Explicit --proxy wins; otherwise trust_env picks up
                # HTTP_PROXY/HTTPS_PROXY (Burp/Caido/ZAP setups).
                session.proxies = {"http": self.cfg.proxy, "https": self.cfg.proxy}
            self._tls.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def close(self) -> None:
        """Close every session this client created; idempotent.

        Sessions live in worker threads' thread-locals, so they cannot be
        closed from their own thread; the registry lets run_scans() release
        sockets and pooled connections once the pool has drained.
        """
        with self._sessions_lock:
            sessions, self._sessions = self._sessions, []
        for sess in sessions:
            try:
                sess.close()
            except Exception:  # noqa: BLE001 - closing must not fail the run
                log.debug("session close failed", exc_info=True)

    def scan(self, url: str) -> ScanResult:
        cfg = self.cfg
        result = ScanResult(url=url, status="fail")
        started = time.monotonic()
        last_error = "retries exhausted"

        for attempt in range(cfg.retries + 1):
            result.attempts = attempt + 1
            if cfg.delay and attempt == 0:
                time.sleep(cfg.delay)
            self.rate_limiter.wait()

            try:
                resp = self._session().get(
                    url,
                    timeout=cfg.timeout,
                    verify=cfg.verify_tls,
                    allow_redirects=cfg.follow_redirects,
                    stream=True,
                )
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                log.debug("%s attempt %d/%d failed: %s", url, attempt + 1, cfg.retries + 1, last_error)
                if attempt < cfg.retries and _is_retryable_exc(exc):
                    time.sleep(compute_backoff(attempt, cfg.backoff, cfg.max_backoff))
                    continue
                result.error = last_error
                result.elapsed = time.monotonic() - started
                return result

            result.http_status = resp.status_code
            result.final_url = str(getattr(resp, "url", None) or url)
            try:
                if resp.status_code in RETRY_STATUSES and attempt < cfg.retries:
                    wait = retry_after_seconds(resp)
                    if wait is None:
                        wait = compute_backoff(attempt, cfg.backoff, cfg.max_backoff)
                    elif wait > cfg.max_wait:
                        # Honor Retry-After, but never park a worker for a
                        # day because a server (or WAF) asked us to.
                        log.debug("%s Retry-After %.0fs capped to --max-wait %.0fs",
                                  url, wait, cfg.max_wait)
                        wait = cfg.max_wait
                    log.debug("%s got HTTP %d, retrying in %.1fs", url, resp.status_code, wait)
                    time.sleep(wait)
                    continue

                if resp.status_code >= 400:
                    # Exhausted retries on a retryable status, or a hard 4xx.
                    result.error = f"HTTP {resp.status_code}"
                    result.elapsed = time.monotonic() - started
                    return result

                content_type = resp.headers.get("Content-Type") if resp.headers else None
                result.content_type = content_type
                if not cfg.parse_all and not should_parse_content_type(content_type):
                    # Binary body: recorded as "skip" (not a failure) so a PDF
                    # on the URL never fails the run or pollutes triage.
                    result.status = "skip"
                    result.error = f"non-HTML content-type: {str(content_type).split(';')[0].strip()}"
                    log.debug("%s skipped: %s", url, result.error)
                    return result

                body, truncated = _read_body(resp, cfg.max_bytes)
                result.truncated = truncated
                if truncated:
                    log.warning("%s body exceeds %d-byte cap, truncating", url, cfg.max_bytes)

                result.comments = extract_comments(make_soup(body))
                result.interesting = triage_comments(result.comments)
                result.status = "ok"
                result.elapsed = time.monotonic() - started
                return result
            except requests.RequestException as exc:
                # Connection dropped (or decoding failed) while reading the
                # body: an ordinary transient network error that gets the
                # same retry policy as a failed connect. In v3.0 these
                # escaped scan() entirely and were misreported as
                # permanent "internal" errors.
                last_error = f"{type(exc).__name__}: {exc}"
                log.debug("%s body read failed (attempt %d/%d): %s",
                          url, attempt + 1, cfg.retries + 1, last_error)
                if attempt < cfg.retries and _is_retryable_exc(exc):
                    time.sleep(compute_backoff(attempt, cfg.backoff, cfg.max_backoff))
                    continue
                result.error = last_error
                result.elapsed = time.monotonic() - started
                return result
            finally:
                resp.close()

        # Unreachable: every path above returns on the final attempt.
        result.error = last_error or "retries exhausted"
        result.elapsed = time.monotonic() - started
        return result


def _is_retryable_exc(exc: requests.RequestException) -> bool:
    # SSLError subclasses ConnectionError but never fixes itself on retry.
    if isinstance(exc, requests.exceptions.SSLError):
        return False
    return isinstance(exc, (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.ChunkedEncodingError,
    ))


def _read_body(resp: requests.Response, max_bytes: int) -> tuple[bytes, bool]:
    """Read at most max_bytes of the decoded body; returns (body, truncated).

    Uses the public resp.iter_content() rather than the semi-private
    resp.raw.read(): raw reads raise *unwrapped* urllib3 errors
    (ProtocolError, ReadTimeoutError) that are not requests.RequestException,
    so a connection reset mid-download would bypass the retry policy
    entirely. iter_content applies content-encoding decoding, re-raises
    those failures as requests exceptions the retry loop already handles,
    and still lets us stop at the size cap (the underlying connection is
    released by resp.close() in scan()'s finally).
    """
    buf = bytearray()
    truncated = False
    for chunk in resp.iter_content(chunk_size=64 * 1024):
        if not chunk:  # keep-alive frames / empty reads
            continue
        buf.extend(chunk)
        if len(buf) > max_bytes:
            truncated = True
            break
    return bytes(buf[:max_bytes]), truncated


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def run_scans(urls: Sequence[str], cfg: ScanConfig) -> list[ScanResult]:
    """Scan every URL concurrently; returns results in completion order.

    ThreadPoolExecutor rather than asyncio: the HTTP layer is `requests`,
    a blocking library, and the per-target work is I/O-bound plus some
    parsing - threads give real concurrency without dragging in an async
    HTTP stack (httpx/aiohttp) for a single-file tool. The GIL is not a
    bottleneck here because socket waits and lxml parsing release it.

    Robustness contract:
    - a scanner bug on one target becomes a failed result, never a lost run;
    - Ctrl+C cancels queued scans and keeps finished ones, and a *second*
      Ctrl+C while in-flight scans drain is caught as well, so partial
      results still reach disk;
    - sessions are closed in `finally`, however the pool exits.
    """
    client = HttpClient(cfg)
    results: dict[str, ScanResult] = {}
    futures: dict[Future, str] = {}
    workers = max(1, min(cfg.workers, len(urls)))
    total = len(urls)

    def collect(fut: Future, url: str) -> None:
        """Store one future's result; a scanner bug must never lose the run."""
        if url in results:  # already collected (interrupt double-pass)
            return
        try:
            res = fut.result()
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            log.exception("internal error scanning %s", url)
            res = ScanResult(url=url, status="fail", error=f"internal: {exc}")
        results[url] = res
        done = len(results)
        if res.status == "ok":
            log.info("[%d/%d] [ok] %s (HTTP %s) %d comment(s), %d flagged in %.2fs",
                     done, total, res.url, res.http_status,
                     len(res.comments), len(res.interesting), res.elapsed)
        elif res.status == "skip":
            log.info("[%d/%d] [skip] %s: %s", done, total, res.url, res.error)
        else:
            log.warning("[%d/%d] [fail] %s: %s", done, total, res.url, res.error)

    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as pool:
            futures = {pool.submit(client.scan, u): u for u in urls}
            try:
                for fut in as_completed(futures):
                    collect(fut, futures[fut])
            except KeyboardInterrupt:
                # Cancel queued work *before* leaving the with-block:
                # executor shutdown then only waits for in-flight scans.
                pending = sum(1 for f in futures if not f.done())
                log.warning("interrupted - cancelling %d queued scan(s), writing partial results", pending)
                for fut in futures:
                    fut.cancel()
                for fut in futures:
                    if fut.done() and not fut.cancelled():
                        collect(fut, futures[fut])
    except KeyboardInterrupt:
        # Second Ctrl+C: arrived while in-flight scans were draining inside
        # executor shutdown. Keep whatever finished instead of crashing
        # before the reports are written.
        log.warning("interrupted again - writing partial results")
        for fut in futures:
            if fut.done() and not fut.cancelled():
                collect(fut, futures[fut])
    finally:
        client.close()
    return list(results.values())


def load_targets(args: argparse.Namespace) -> list[str]:
    """Collect, validate and de-duplicate targets from args and/or a file.

    The file is streamed line-by-line - recon lists can hold hundreds of
    thousands of URLs and read_text() would hold them all in memory at
    once - and duplicates collapse by dedup_key(), so trivial spelling
    differences ("a.test" vs "a.test/" vs "A.test") scan once.
    """
    def iter_raw() -> Iterator[str]:
        yield from args.targets
        if args.file:
            path = Path(args.file)
            if not path.is_file():
                log.error("target file not found: %s", args.file)
                raise SystemExit(1)
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    yield line

    seen: set[str] = set()
    urls: list[str] = []
    for item in iter_raw():
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        url = normalize_url(item)
        if url is None:
            log.warning("skipping invalid target: %r", item)
            continue
        key = dedup_key(url)
        if key in seen:
            continue
        seen.add(key)
        urls.append(url)
    return urls


def write_outputs(results: Sequence[ScanResult], out_json: Path, out_txt: Path | None) -> None:
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "comment2enum",
        "version": VERSION,
        "targets": len(results),
        "ok": sum(1 for r in results if r.status == "ok"),
        "skipped": sum(1 for r in results if r.status == "skip"),
        "failed": sum(1 for r in results if r.status == "fail"),
        "results": [r.to_dict() for r in results],
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("JSON report: %s", out_json)

    if out_txt is None:
        return
    lines: list[str] = []
    for r in results:
        if r.status != "ok" or not r.comments:
            continue
        lines.append(f"# {r.url}")
        for i, comment in enumerate(r.comments, 1):
            hit = next((h for h in r.interesting if h["index"] == i), None)
            tag = f"  [{','.join(hit['labels'])}]" if hit else ""
            lines.append(f"--- comment {i}{tag} ---")
            lines.append(comment)
        lines.append("")
    out_txt.parent.mkdir(parents=True, exist_ok=True)
    out_txt.write_text("\n".join(lines), encoding="utf-8")
    log.info("Text dump: %s", out_txt)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors exit 1 instead of argparse's 2.

    comment2enum reserves exit code 2 for "the scan ran but one or more
    targets failed"; argparse's default error() would make a typo in a
    pipeline look like a partial scan failure.
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="comment2enum",
        description="Extract and triage hidden HTML comments from web targets "
                    "(authorized security testing only).",
        epilog="examples:\n"
               "  comment2enum.py https://target.com\n"
               "  comment2enum.py -f urls.txt --proxy http://127.0.0.1:8080 -w 8\n"
               "  comment2enum.py http://10.129.60.23 --insecure -o engagement42/\n"
               "note: bare hostnames are normalized to https://; pass http:// explicitly "
               "for plaintext targets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", metavar="URL", help="target URL(s)")
    p.add_argument("-f", "--file", help="file with one URL per line ('#' comments allowed)")
    p.add_argument("-o", "--outdir", help="output directory (default: comments_<UTC stamp>)")
    p.add_argument("-w", "--workers", type=int, default=5, help="concurrent scans (default: 5)")
    p.add_argument("-t", "--timeout", type=float, default=15.0, help="per-request timeout in seconds (default: 15)")
    p.add_argument("-R", "--retries", type=int, default=3, help="retries per target (default: 3)")
    p.add_argument("--backoff", type=float, default=1.0, help="retry backoff base in seconds (default: 1)")
    p.add_argument("--delay", type=float, default=0.0, help="seconds to sleep before each target's first request")
    p.add_argument("--max-size", type=int, default=2_000_000, help="response body cap in bytes (default: 2000000)")
    p.add_argument("--rps", type=float, default=None, metavar="N",
                   help="max request starts per second across all workers (default: unlimited)")
    p.add_argument("--max-wait", type=float, default=60.0,
                   help="cap in seconds for a server-supplied Retry-After (default: 60)")
    p.add_argument("--parse-all", action="store_true",
                   help="parse bodies even when Content-Type is not HTML/XML (disables the binary skip gate)")
    p.add_argument("--proxy", default=os.environ.get("AD2ENUM_PROXY"),
                   help="proxy URL for http+https (also AD2ENUM_PROXY / HTTP(S)_PROXY env)")
    p.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    p.add_argument("--no-redirects", action="store_true", help="do not follow redirects")
    p.add_argument("-A", "--user-agent", default=DEFAULT_UA, help="override User-Agent")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                   help="extra request header (repeatable); wins over built-in headers")
    p.add_argument("--cookie", default=None, metavar="PAIRS",
                   help="Cookie header for authenticated scans, e.g. 'sid=abc; role=admin'")
    p.add_argument("--config", metavar="FILE",
                   help="JSON file of option defaults (precedence: CLI > env > config > built-in)")
    p.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors")
    p.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    p.add_argument("--version", action="version", version=f"comment2enum {VERSION}")
    return p


def load_config_file(path: str) -> dict[str, Any]:
    """Read a JSON object of argparse-dest keys; raises ValueError on problems."""
    file = Path(path)
    if not file.is_file():
        raise ValueError(f"config file not found: {path}")
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"config {path} must contain a JSON object of option defaults")
    return data


def _env_overrides() -> dict[str, Any]:
    """COMMENT2ENUM_* environment variables -> parser defaults.

    Applied after the config file so the precedence is
    CLI > env > config file > built-in defaults. Invalid values are
    ignored with a warning rather than crashing an otherwise valid run.
    """
    specs: dict[str, tuple[str, Any]] = {
        "WORKERS": ("workers", int),
        "TIMEOUT": ("timeout", float),
        "RETRIES": ("retries", int),
        "BACKOFF": ("backoff", float),
        "DELAY": ("delay", float),
        "RPS": ("rps", float),
        "MAX_SIZE": ("max_size", int),
        "PROXY": ("proxy", str),
        "USER_AGENT": ("user_agent", str),
        "OUTDIR": ("outdir", str),
    }
    overrides: dict[str, Any] = {}
    for suffix, (dest, cast) in specs.items():
        raw = os.environ.get(f"COMMENT2ENUM_{suffix}")
        if raw is None or raw == "":
            continue
        try:
            overrides[dest] = cast(raw)
        except ValueError:
            log.warning("ignoring invalid COMMENT2ENUM_%s=%r (expected %s)",
                        suffix, raw, getattr(cast, "__name__", cast))
    return overrides


def apply_config(parser: argparse.ArgumentParser, argv: Sequence[str]) -> None:
    """Layer config-file and environment defaults beneath CLI arguments.

    argparse can only accept defaults *before* parse_args(), so --config is
    pre-scanned here and set_defaults() layers file values first, env values
    second. Whatever parse_args() finally produces still has
    CLI > env > config > built-in precedence. Config errors log and raise
    SystemExit(1) (usage-error territory, not scan failure).
    """
    pre = _Parser(add_help=False)
    pre.add_argument("--config", dest="config")
    try:
        pre_args, _ = pre.parse_known_args(list(argv))
    except SystemExit:
        return  # malformed --config; the full parser reports it properly
    if not pre_args.config:
        return

    try:
        file_cfg = load_config_file(pre_args.config)
    except ValueError as exc:
        log.error("%s", exc)
        raise SystemExit(1) from exc

    # argparse internals: _actions is stable across CPython versions and
    # is the only way to enumerate valid dests without duplicating them.
    valid = {a.dest for a in parser._actions if a.dest != argparse.SUPPRESS}  # noqa: SLF001
    reserved = {"config", "targets"}  # no config-of-config, no positional URLs
    unknown = sorted(k for k in file_cfg if k in reserved or k not in valid)
    if unknown:
        log.error("unknown/unsupported key(s) in %s: %s", pre_args.config, ", ".join(unknown))
        raise SystemExit(1)
    if file_cfg:
        parser.set_defaults(**file_cfg)

    env_cfg = _env_overrides()
    if env_cfg:
        parser.set_defaults(**env_cfg)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Logging first so config/env problems are reported through it; the
    # -q/-v level is applied right after parsing.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s [%(threadName)s] %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    parser = build_parser()
    try:
        apply_config(parser, argv)
    except SystemExit:
        return 1  # apply_config already logged the reason
    # Usage errors exit 1 (see _Parser); --help/--version exit 0.
    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logging.getLogger().setLevel(level)

    # ---- input validation: reject nonsensical/hostile values up front ----
    if not 1 <= args.workers <= 512:
        log.error("--workers must be between 1 and 512 (got %s)", args.workers)
        return 1
    if not 0 <= args.retries <= 20:
        log.error("--retries must be between 0 and 20 (got %s)", args.retries)
        return 1
    if args.timeout <= 0:
        log.error("--timeout must be > 0 (got %s)", args.timeout)
        return 1
    if args.backoff < 0 or args.max_wait < 0 or args.delay < 0:
        log.error("--backoff, --max-wait and --delay must be >= 0")
        return 1
    if args.max_size < 1:
        log.error("--max-size must be >= 1 (got %s)", args.max_size)
        return 1
    if args.rps is not None and args.rps <= 0:
        log.error("--rps must be > 0 (got %s)", args.rps)
        return 1

    # Headers/cookies reach the wire verbatim: validate before use so a
    # config file or wrapper script cannot smuggle CR/LF into the request.
    headers: dict[str, str] = {}
    try:
        raw_headers = [args.header] if isinstance(args.header, str) else list(args.header or [])
        for raw_h in raw_headers:
            name, value = parse_header(str(raw_h))
            headers[name] = value
        if args.cookie is not None:
            if not isinstance(args.cookie, str):
                raise ValueError("--cookie must be a string")
            validate_cookie(args.cookie)
    except (ValueError, TypeError) as exc:
        log.error("%s", exc)
        return 1

    urls = load_targets(args)
    if not urls:
        log.error("no valid targets (give URL(s) positionally and/or -f FILE)")
        return 1

    if args.insecure and urllib3 is not None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cfg = ScanConfig(
        timeout=args.timeout,
        retries=args.retries,
        backoff=args.backoff,
        delay=args.delay,
        max_bytes=args.max_size,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        user_agent=args.user_agent,
        follow_redirects=not args.no_redirects,
        workers=args.workers,
        rps=args.rps,
        max_wait=args.max_wait,
        headers=headers,
        cookie=args.cookie if isinstance(args.cookie, str) else None,
        parse_all=args.parse_all,
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.outdir or f"comments_{stamp}")
    rate_note = f" at <= {cfg.rps:g} req/s" if cfg.rps else ""
    log.info("scanning %d target(s) with %d worker(s)%s; output: %s",
             len(urls), cfg.workers, rate_note, outdir)

    results = run_scans(urls, cfg)
    results.sort(key=lambda r: r.url)
    try:
        write_outputs(results, outdir / "found_comments.json", outdir / "found_comments.txt")
    except OSError as exc:
        # The scan succeeded; a full disk or missing permission must not
        # surface as a raw traceback.
        log.error("cannot write reports to %s: %s", outdir, exc)
        return 1

    ok = sum(1 for r in results if r.status == "ok")
    skipped = sum(1 for r in results if r.status == "skip")
    failed = sum(1 for r in results if r.status == "fail")
    total = sum(len(r.comments) for r in results)
    flagged = sum(len(r.interesting) for r in results)
    log.info("done: %d/%d target(s) ok, %d skipped, %d failed; %d comment(s), %d flagged interesting",
             ok, len(results), skipped, failed, total, flagged)
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())