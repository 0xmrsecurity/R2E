"""Unit tests for comment2enum. No network access: HTTP is fully faked."""

import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "Comments"))

import comment2enum as c2  # noqa: E402


# ---------------------------------------------------------------- URL handling

@pytest.mark.parametrize("raw,expected", [
    ("target.com", "https://target.com"),
    ("  http://target.com/a  ", "http://target.com/a"),
    ("https://10.129.60.23:8443/x", "https://10.129.60.23:8443/x"),
    ("https://[2001:db8::1]/", "https://[2001:db8::1]/"),
])
def test_normalize_url_ok(raw, expected):
    assert c2.normalize_url(raw) == expected


@pytest.mark.parametrize("raw", [
    "",
    "   ",
    "ftp://x.com",
    "javascript:alert(1)",
    "https://bad host/",
    "file:///etc/passwd",
])
def test_normalize_url_rejects(raw):
    assert c2.normalize_url(raw) is None


def test_load_targets_dedup_order_and_invalid(tmp_path):
    lst = tmp_path / "urls.txt"
    lst.write_text(
        "# a comment\n"
        "https://a.test\n"
        "bare.host\n"
        "https://a.test\n"
        "\n"
        "ftp://bad\n",
        encoding="utf-8",
    )
    ns = argparse_ns(targets=["https://c.test"], file=str(lst))
    urls = c2.load_targets(ns)
    assert urls == ["https://c.test", "https://a.test", "https://bare.host"]


def test_load_targets_missing_file(tmp_path):
    ns = argparse_ns(targets=[], file=str(tmp_path / "nope.txt"))
    with pytest.raises(SystemExit):
        c2.load_targets(ns)


# ------------------------------------------------------------------- backoff

def test_backoff_bounds_per_attempt():
    random.seed(1234)
    for attempt in range(5):
        value = c2.compute_backoff(attempt, base=1.0, cap=30.0)
        assert 0.0 <= value <= min(30.0, 2 ** attempt)


def test_backoff_respects_cap():
    random.seed(99)
    assert c2.compute_backoff(20, base=1.0, cap=5.0) <= 5.0


# --------------------------------------------------------------- Retry-After

class _HeaderResp:
    def __init__(self, headers):
        self.headers = headers


def test_retry_after_delta_seconds():
    assert c2.retry_after_seconds(_HeaderResp({"Retry-After": "7"})) == 7.0


def test_retry_after_http_date():
    when = datetime.now(timezone.utc) + timedelta(seconds=10)
    value = c2.retry_after_seconds(_HeaderResp({"Retry-After": format_datetime(when)}))
    assert value is not None and 0 < value <= 10


def test_retry_after_garbage_returns_none():
    assert c2.retry_after_seconds(_HeaderResp({"Retry-After": "soon"})) is None


def test_retry_after_absent_returns_none():
    assert c2.retry_after_seconds(_HeaderResp({})) is None


# ---------------------------------------------------------- comment extraction

HTML = (
    b"<html><body>"
    b"<!-- TODO: rotate creds -->"
    b"<p>hello</p>"
    b"<!--   password: S3cr3t! 192.168.10.5   -->"
    b"<!--    -->"
    b"</body></html>"
)


def test_make_soup_falls_back_without_lxml():
    # Must not raise regardless of lxml presence.
    assert c2.make_soup(HTML) is not None


def test_extract_comments_skips_blank():
    comments = c2.extract_comments(c2.make_soup(HTML))
    assert comments == ["TODO: rotate creds", "password: S3cr3t! 192.168.10.5"]


def test_triage_comments_labels():
    hits = c2.triage_comments(c2.extract_comments(c2.make_soup(HTML)))
    by_index = {h["index"]: set(h["labels"]) for h in hits}
    assert "todo" in by_index[1]
    assert {"credential", "internal-ip"} <= by_index[2]


def test_triage_snippet_bounded():
    long_comment = "password " + "A" * 500
    hits = c2.triage_comments([long_comment])
    assert len(hits) == 1
    assert len(hits[0]["text"]) <= 304  # 300 chars + "..."


# ------------------------------------------------------------------ scanning

class FakeRaw:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, amt=None, decode_content=False):
        return self._data if amt is None else self._data[:amt]


class FakeResp:
    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None,
                 url: str | None = None, read_error: Exception | None = None):
        self.status_code = status
        self.raw = FakeRaw(body)
        self.headers = headers or {}
        self.url = url
        self.closed = False
        self._body = body
        self._read_error = read_error  # raised once at the start of the body read

    def iter_content(self, chunk_size: int = 1):
        """Mimic requests.Response.iter_content (public streaming API)."""
        if self._read_error is not None:
            err, self._read_error = self._read_error, None
            raise err
        data = self._body
        for start in range(0, len(data), chunk_size):
            yield data[start:start + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    """Returns scripted outcomes; raises them when the outcome is an exception."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0

    def get(self, url, **kwargs):
        self.calls += 1
        item = self._outcomes.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _client(retries: int = 2, **cfg_kw) -> c2.HttpClient:
    cfg = c2.ScanConfig(retries=retries, backoff=0.001, max_backoff=0.002, **cfg_kw)
    return c2.HttpClient(cfg)


def _install(client: c2.HttpClient, session: FakeSession) -> None:
    client._tls.session = session


def test_scan_success_first_attempt():
    client = _client()
    _install(client, FakeSession([FakeResp(200, b"<!-- hi -->")]))
    res = client.scan("https://x.test/")
    assert res.status == "ok"
    assert res.http_status == 200
    assert res.comments == ["hi"]
    assert res.attempts == 1


def test_scan_retries_5xx_then_succeeds():
    client = _client()
    session = FakeSession([FakeResp(503), FakeResp(200, b"<!-- a -->")])
    _install(client, session)
    res = client.scan("https://x.test/")
    assert res.status == "ok"
    assert res.attempts == 2
    assert session.calls == 2


def test_scan_exhausts_retries_on_persistent_5xx():
    client = _client(retries=2)
    session = FakeSession([FakeResp(500), FakeResp(500), FakeResp(500)])
    _install(client, session)
    res = client.scan("https://x.test/")
    assert res.status == "fail"
    assert res.error == "HTTP 500"
    assert session.calls == 3


def test_scan_honors_retry_after_zero():
    client = _client()
    _install(client, FakeSession([
        FakeResp(429, headers={"Retry-After": "0"}),
        FakeResp(200, b"<!-- ok -->"),
    ]))
    res = client.scan("https://x.test/")
    assert res.status == "ok" and res.attempts == 2


def test_scan_4xx_fails_without_retry():
    client = _client()
    session = FakeSession([FakeResp(404)])
    _install(client, session)
    res = client.scan("https://x.test/")
    assert res.status == "fail"
    assert res.error == "HTTP 404"
    assert session.calls == 1  # no wasted quota on deterministic 4xx


def test_scan_connection_error_is_retried():
    client = _client()
    _install(client, FakeSession([
        requests.exceptions.ConnectTimeout("timed out"),
        FakeResp(200, b"<!-- z -->"),
    ]))
    res = client.scan("https://x.test/")
    assert res.status == "ok" and res.attempts == 2


def test_scan_ssl_error_is_not_retried():
    client = _client()
    session = FakeSession([requests.exceptions.SSLError("bad cert")])
    _install(client, session)
    res = client.scan("https://x.test/")
    assert res.status == "fail"
    assert res.attempts == 1
    assert "SSLError" in (res.error or "")


def test_scan_body_cap_truncates_but_still_parses():
    client = _client()
    client.cfg.max_bytes = 16
    body = b"<!-- x -->" + b"A" * 100
    _install(client, FakeSession([FakeResp(200, body)]))
    res = client.scan("https://x.test/")
    assert res.status == "ok"
    assert res.comments == ["x"]


def test_scan_closes_response():
    client = _client()
    resp = FakeResp(200, b"<!-- c -->")
    _install(client, FakeSession([resp]))
    client.scan("https://x.test/")
    assert resp.closed  # no socket leak per scan


# ------------------------------------------------------------- results/output

def argparse_ns(targets, file=None):
    import argparse
    return argparse.Namespace(targets=targets, file=file)


def test_result_to_dict_shape():
    r = c2.ScanResult(url="u", status="ok", http_status=200, comments=["c"])
    d = r.to_dict()
    assert d["url"] == "u"
    assert d["comment_count"] == 1
    assert d["interesting"] == []


def test_write_outputs_json_and_txt(tmp_path):
    results = [
        c2.ScanResult(
            url="https://a.test", status="ok", http_status=200,
            comments=["TODO: x"],
            interesting=[{"index": 1, "labels": ["todo"], "text": "TODO: x"}],
        ),
        c2.ScanResult(url="https://b.test", status="fail", error="HTTP 404"),
    ]
    out_json = tmp_path / "nested" / "found_comments.json"
    out_txt = tmp_path / "nested" / "comments.txt"
    c2.write_outputs(results, out_json, out_txt)

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["targets"] == 2
    assert data["ok"] == 1
    assert data["failed"] == 1
    assert data["results"][0]["comment_count"] == 1

    txt = out_txt.read_text(encoding="utf-8")
    assert "https://a.test" in txt
    assert "TODO: x" in txt
    assert "[todo]" in txt
    assert "https://b.test" not in txt  # failures are not dumped to text


def test_run_scans_collects_internal_errors(monkeypatch):
    """A scanner bug on one URL must not lose results for the others."""
    cfg = c2.ScanConfig(retries=0, backoff=0.001, workers=2)
    client_calls = {"n": 0}
    original_scan = c2.HttpClient.scan

    def flaky_scan(self, url):
        client_calls["n"] += 1
        if "boom" in url:
            raise RuntimeError("scanner bug")
        return original_scan(self, url)

    monkeypatch.setattr(c2.HttpClient, "scan", flaky_scan)
    sessions = iter([
        FakeSession([FakeResp(200, b"<!-- good -->")]),
    ])

    def fake_session_factory(self):
        return next(sessions)

    monkeypatch.setattr(c2.HttpClient, "_session", fake_session_factory)

    results = c2.run_scans(["https://boom.test/", "https://ok.test/"], cfg)
    assert len(results) == 2
    by_url = {r.url: r for r in results}
    assert by_url["https://boom.test/"].status == "fail"
    assert "internal" in (by_url["https://boom.test/"].error or "")
    assert by_url["https://ok.test/"].status == "ok"


# ---------------------------------------------------------------------- CLI

def test_main_no_targets_returns_1(capsys):
    assert c2.main([]) == 1


def test_main_invalid_workers_returns_1():
    assert c2.main(["https://x.test", "--workers", "0"]) == 1


def test_parser_defaults_roundtrip():
    args = c2.build_parser().parse_args(["https://a.test", "-f", "b.txt", "-w", "3", "--insecure"])
    assert args.targets == ["https://a.test"]
    assert args.file == "b.txt"
    assert args.workers == 3
    assert args.insecure is True
    assert not hasattr(args, "verify")  # TLS verify is derived in main(), not a flag


# ------------------------------------------------------------------ v3.1: URLs

def test_normalize_url_strips_fragment():
    assert c2.normalize_url("https://a.test/page#section") == "https://a.test/page"


def test_dedup_key_collapses_spellings():
    assert c2.dedup_key("https://A.test") == c2.dedup_key("https://a.test/")
    assert c2.dedup_key("https://a.test:443/#x") == c2.dedup_key("https://a.test/")
    assert c2.dedup_key("http://a.test:80/") == c2.dedup_key("http://a.test/")
    assert c2.dedup_key("https://a.test/other") != c2.dedup_key("https://a.test/")
    assert c2.dedup_key("https://a.test/?q=1") != c2.dedup_key("https://a.test/")


def test_load_targets_dedup_by_key(tmp_path):
    lst = tmp_path / "u.txt"
    lst.write_text("https://a.test\nhttps://a.test/\nhttps://A.TEST#top\n", encoding="utf-8")
    ns = argparse_ns(targets=[], file=str(lst))
    assert c2.load_targets(ns) == ["https://a.test"]


# ------------------------------------------------------- v3.1: header/cookie

@pytest.mark.parametrize("raw,expected", [
    ("X-Api-Key: abc123", ("X-Api-Key", "abc123")),
    ("Authorization:Bearer tok", ("Authorization", "Bearer tok")),
    ("X-Empty:", ("X-Empty", "")),
])
def test_parse_header_ok(raw, expected):
    assert c2.parse_header(raw) == expected


@pytest.mark.parametrize("raw", [
    "X-A: ok\r\nX-Injected: 1",  # CRLF request smuggling
    "no-colon-here",
    ": empty name",
    "Bad Name: v",  # whitespace is not an RFC 7230 token
])
def test_parse_header_rejects(raw):
    with pytest.raises(ValueError):
        c2.parse_header(raw)


def test_validate_cookie():
    assert c2.validate_cookie("a=b; c=d") == "a=b; c=d"
    with pytest.raises(ValueError):
        c2.validate_cookie("a=b\r\nX-Injected: 1")


# ----------------------------------------------------- v3.1: content-type gate

@pytest.mark.parametrize("ct,expected", [
    (None, True),
    ("", True),
    ("text/html; charset=utf-8", True),
    ("application/xhtml+xml", True),
    ("application/json", True),
    ("text/plain", True),
    ("application/pdf", False),
    ("image/png", False),
    ("application/octet-stream", False),
    ("application/zip", False),
])
def test_should_parse_content_type(ct, expected):
    assert c2.should_parse_content_type(ct) is expected


def test_scan_skips_binary_content_type():
    client = _client()
    session = FakeSession([FakeResp(200, b"%PDF-1.7\x00\x00",
                                    headers={"Content-Type": "application/pdf"})])
    _install(client, session)
    res = client.scan("https://x.test/doc.pdf")
    assert res.status == "skip"
    assert res.content_type == "application/pdf"
    assert "application/pdf" in (res.error or "")
    assert res.comments == []
    assert session.calls == 1  # no retry on a skip


def test_scan_parse_all_overrides_gate():
    client = _client(parse_all=True)
    _install(client, FakeSession([
        FakeResp(200, b"<!-- c -->", headers={"Content-Type": "application/octet-stream"}),
    ]))
    res = client.scan("https://x.test/")
    assert res.status == "ok" and res.comments == ["c"]


# ------------------------------------------------------- v3.1: scan robustness

def test_scan_retries_mid_body_failure():
    """A connection drop *while downloading* must retry like a failed connect."""
    client = _client()
    session = FakeSession([
        FakeResp(200, b"<!-- lost -->",
                 read_error=requests.exceptions.ConnectionError("reset")),
        FakeResp(200, b"<!-- recovered -->"),
    ])
    _install(client, session)
    res = client.scan("https://x.test/")
    assert res.status == "ok"
    assert res.attempts == 2
    assert res.comments == ["recovered"]
    assert session.calls == 2


def test_scan_retry_after_capped():
    """A hostile 'Retry-After: 9999' must not park the worker for hours."""
    client = _client(max_wait=0.01)
    session = FakeSession([
        FakeResp(429, headers={"Retry-After": "9999"}),
        FakeResp(200, b"<!-- ok -->"),
    ])
    _install(client, session)
    res = client.scan("https://x.test/")
    assert res.status == "ok" and res.attempts == 2
    assert session.calls == 2


def test_scan_records_final_url_and_truncation_flag():
    client = _client()
    client.cfg.max_bytes = 8
    resp = FakeResp(200, b"<!-- hello world -->", url="https://x.test/final")
    _install(client, FakeSession([resp]))
    res = client.scan("https://x.test/")
    assert res.final_url == "https://x.test/final"
    assert res.truncated is True


def test_scan_not_truncated_when_body_fits():
    client = _client()
    _install(client, FakeSession([FakeResp(200, b"<!-- small -->")]))
    res = client.scan("https://x.test/")
    assert res.status == "ok"
    assert res.truncated is False
    assert res.content_type is None  # missing header still parses


# --------------------------------------------------------- v3.1: rate limiting

def test_rate_limiter_none_is_noop():
    limiter = c2.RateLimiter(None)
    start = time.monotonic()
    for _ in range(50):
        limiter.wait()
    assert time.monotonic() - start < 0.5


def test_rate_limiter_spaces_starts():
    limiter = c2.RateLimiter(100)  # 10 ms between request starts
    start = time.monotonic()
    for _ in range(3):
        limiter.wait()
    assert time.monotonic() - start >= 0.012  # 2 intervals, loose bound


def test_rate_limiter_disabled_by_zero():
    limiter = c2.RateLimiter(0)
    start = time.monotonic()
    for _ in range(100):
        limiter.wait()
    assert time.monotonic() - start < 0.5


# ----------------------------------------------------------- v3.1: resources

def test_http_client_close_releases_sessions():
    client = _client()
    client._session()  # creates a real (never used) session
    assert len(client._sessions) == 1
    client.close()
    assert client._sessions == []
    client.close()  # idempotent
    assert client._sessions == []


# ------------------------------------------------------------- v3.1: config/env

def test_config_file_sets_defaults(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"workers": 7, "timeout": 3.0, "insecure": True}),
                   encoding="utf-8")
    parser = c2.build_parser()
    c2.apply_config(parser, ["--config", str(cfg)])
    args = parser.parse_args(["https://a.test"])
    assert args.workers == 7 and args.timeout == 3.0 and args.insecure is True


def test_config_file_cli_wins(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"workers": 7}), encoding="utf-8")
    parser = c2.build_parser()
    c2.apply_config(parser, ["--config", str(cfg)])
    args = parser.parse_args(["https://a.test", "-w", "2"])
    assert args.workers == 2


def test_config_file_unknown_or_reserved_key_exits(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"targets": ["x"], "bogus": 1}), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        c2.apply_config(c2.build_parser(), ["--config", str(cfg)])
    assert exc.value.code == 1


def test_config_file_invalid_json_exits(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        c2.apply_config(c2.build_parser(), ["--config", str(cfg)])
    assert exc.value.code == 1


def test_config_file_missing_exits():
    with pytest.raises(SystemExit) as exc:
        c2.apply_config(c2.build_parser(), ["--config", "definitely-missing.json"])
    assert exc.value.code == 1


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("COMMENT2ENUM_WORKERS", "9")
    monkeypatch.setenv("COMMENT2ENUM_TIMEOUT", "2.5")
    monkeypatch.setenv("COMMENT2ENUM_RPS", "not-a-number")  # warned + ignored
    overrides = c2._env_overrides()
    assert overrides["workers"] == 9
    assert overrides["timeout"] == 2.5
    assert "rps" not in overrides


def test_usage_errors_exit_1_not_2():
    """Exit 2 is reserved for 'the scan ran but targets failed'."""
    with pytest.raises(SystemExit) as exc:
        c2.build_parser().parse_args(["--bogus-flag"])
    assert exc.value.code == 1


# ------------------------------------------------------------------ v3.1: CLI

def test_main_invalid_timeout_returns_1():
    assert c2.main(["https://x.test", "--timeout", "0"]) == 1


def test_main_invalid_rps_returns_1():
    assert c2.main(["https://x.test", "--rps", "-1"]) == 1


def test_main_invalid_workers_upper_bound_returns_1():
    assert c2.main(["https://x.test", "--workers", "5000"]) == 1


def test_main_bad_header_returns_1():
    assert c2.main(["https://x.test", "-H", "no-colon"]) == 1


def test_main_injected_cookie_returns_1():
    assert c2.main(["https://x.test", "--cookie", "a=b\r\nX: 1"]) == 1


def test_main_missing_config_returns_1():
    assert c2.main(["--config", "missing-config.json"]) == 1


def test_result_to_dict_v31_fields():
    r = c2.ScanResult(url="u", status="skip", http_status=200,
                      final_url="https://u/final", content_type="application/pdf",
                      truncated=True, error="non-HTML content-type: application/pdf")
    d = r.to_dict()
    assert d["final_url"] == "https://u/final"
    assert d["content_type"] == "application/pdf"
    assert d["truncated"] is True