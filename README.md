# ad2enum

Active Directory and web enumeration scripts for authorized security testing
(bug bounty recon, pentests, labs).

## Repo structure

```
nmap/
  nmap2enum.sh           live-host discovery + port scan + deep-scan pipeline

rpc/
  rpc2enum.sh            anonymous/authenticated RPC enumeration via rpcclient

bloodhound/
  bloodhound2enum.sh     AD collection: bloodyAD, bloodhound-python, rusthound

git/
  gitcheck2enum.sh       clone + enumerate a git repo (history, dangling objects, secrets)

crawler/
  crawlurl2enum.sh       katana + gospider crawl, endpoint categorization, path probe

Comments/
  comment2enum.py        HTML comment extraction + keyword triage 

requirements.txt         Python runtime dependencies
```

## Python setup

```bash
pip install -r requirements.txt
```

Runtime deps: `requests`, `beautifulsoup4`. Optional: `lxml` (faster parser;
falls back to stdlib `html.parser` when missing).

Run tests:

```bash
python -m pytest tests/ -v
```

## External tools

The shell scripts call these binaries. Install what you need; each script
checks availability and skips steps for missing tools.

| Tool | Used by | Install |
|------|---------|---------|
| nmap | nmap2enum.sh | `apt install nmap` |
| fscan | nmap2enum.sh | [github.com/leadroyal/FSscan](https://github.com/leadroyal/FSscan) |
| fping | nmap2enum.sh | `apt install fping` |
| rpcclient | rpc2enum.sh | `apt install samba-common-bin` |
| nc | rpc2enum.sh | `apt install netcat-openbsd` |
| bloodyAD | bloodhound2enum.sh | [github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD) |
| bloodhound-python | bloodhound2enum.sh | `pip install bloodhound` |
| rusthound | bloodhound2enum.sh | [github.com/SpecterOps/RustHound](https://github.com/SpecterOps/RustHound) |
| net | bloodhound2enum.sh | `apt install samba-common-bin` |
| git | gitcheck2enum.sh | `apt install git` |
| curl | gitcheck2enum.sh, crawlurl2enum.sh | `apt install curl` |
| git-dumper | gitcheck2enum.sh | `pip install git-dumper` |
| trufflehog | gitcheck2enum.sh | `pipx install trufflehog` |
| gitleaks | gitcheck2enum.sh | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| katana | crawlurl2enum.sh | [github.com/ProjectDiscovery/katana](https://github.com/ProjectDiscovery/katana) |
| gospider | crawlurl2enum.sh | [github.com/jaeles-project/gospider](https://github.com/jaeles-project/gospider) |

---

# nmap2enum.sh

Automated live-host discovery + full port scan + deep-scan pipeline.

```bash
./nmap/nmap2enum.sh -t 10.129.60.23
./nmap/nmap2enum.sh -t 10.129.60.0/24
./nmap/nmap2enum.sh -t 10.129.60.23 -r 300 -s 1   # non-interactive: TCP deep scan
```

Options:
- `-t TARGET` — single IP, CIDR, dash-range, or comma list
- `-r N` — nmap `--min-rate` (default 1000; lower on VPN labs)
- `-s 1-5` — skip interactive menu (1=tcp 2=udp 3=both 4=poc-cve 5=everything)

Output: `scan_<target>_<timestamp>/` with live-hosts, ports, nmap and fscan logs.

v3 fixes:
- `set -o pipefail` added — pipe failures no longer silently swallowed.
- `-iL` file argument passed as array, not unquoted string (spaces in path safe).
- `[0-9]` grep pattern quoted — unquoted glob could match a stray file named `0-9`.
- `sort -un` instead of `sort -u` — numeric dedup avoids `80` vs `8080` collision.
- `sudo` only when not root and sudo exists — unprivileged connect scan works on modern kernels.
- Non-TTY fallback: defaults to scan 1 instead of hanging on `read`.

---

# rpc2enum.sh

Anonymous or authenticated RPC enumeration via rpcclient.

```bash
./rpc/rpc2enum.sh 10.129.60.23
RPC_USER='j.arbuckle' RPC_PASS='P@ssw0rd' ./rpc2enum.sh 10.129.60.23
RPC_RID_START=500 RPC_RID_END=2000 ./rpc2enum.sh 10.129.60.23   # wider RID cycle
```

Environment variables:
- `RPC_USER` / `RPC_PASS` — credentials (anonymous when unset)
- `RPC_RID_START` / `RPC_RID_END` — RID cycle range (default 500–1100)

Output: `rpc_loot_<IP>_<timestamp>/rpc2enum-console.txt` (chmod 700).

v3 fixes:
- `set -o pipefail` added.
- Local variables renamed from `USER`/`PASS` to `RC_USER`/`RC_PASS` — clobbering
  `$USER` leaked the target username into every child process environment.
- `grep -oP` (GNU PCRE) replaced with portable `sed -n 's/…/\1/p'` — works on BSD/macOS.
- `grep -oP` for domain SID replaced with `grep -oE` + `head -n1` — portable.
- RID range configurable via env vars instead of hardcoded 500–1100.
- `rpcclient` and `nc` availability checked before use.
- Argument parsing rewritten as `while` loop — options and positional target in any order.
- Console output teed to timestamped loot directory automatically.

---

# bloodhound2enum.sh

AD enumeration + BloodHound collection (bloodyAD, bloodhound-python, rusthound).

```bash
./bloodhound/bloodhound2enum.sh -f dc01.garfield.htb -d garfield.htb -i 10.129.60.23 -u user -p 'pass'
BH_USER='user' BH_PASS='pass' ./bloodhound2enum.sh -f dc01.garfield.htb -d garfield.htb -i 10.129.60.23
```

Output: `bh_loot_<DOMAIN>_<timestamp>/` (chmod 700).

v3 fixes:
- `set -o pipefail` added.
- Local variables renamed from `USER`/`PASS` to `BH_USERNAME`/`BHPASS` — same
  environment clobbering bug as rpc2enum.
- Output directory now timestamped — re-runs no longer overwrite previous loot.
- `chmod 700` on loot directory.
- FQDN resolution check falls back to `dig`/`host` when `getent` is absent (non-glibc).
- Security note added to `--help`: password visible in `ps` briefly.

---

# gitcheck2enum.sh

Clone and enumerate a git repository: history, dangling objects, reflog,
submodules, CI files, largest blobs, secret scan.

```bash
./git/gitcheck2enum.sh -u https://git.example.com/app.git
./git/gitcheck2enum.sh -p ./Already-cloned-Repo
```

Output: `git_loot_<repo>_<timestamp>/` (chmod 700) with `full-history.diff`,
`dangling.diff`, `secrets-grep.txt`, `trufflehog.txt`, `gitleaks.txt`.

v3 fixes:
- Bulk dumps written to loot directory instead of flooding console.
- Secret grep pattern rewritten: old pattern matched bare words (`http|host|port|user|db|secret|token`)
  which matched almost every diff line at volume. New pattern matches concrete
  credential shapes: AWS/GitHub/Slack/Stripe key prefixes, PEM blocks,
  `scheme://user:pass@` URIs, and `key=value` assignments with minimum length.
- `rm -rf` guarded: checks `REPO_DIR` is non-empty, not `.` or `/`, and exists
  before deleting (prevents catastrophic deletion on odd `SAFE_NAME`).
- CI file content dumped via `while IFS= read -r f` loop instead of `xargs cat` —
  filenames with spaces no longer break the dump.
- `trufflehog` and `gitleaks` output teed to loot directory.

---

# crawlurl2enum.sh

Crawl a target with katana + gospider, probe common web-root paths, categorize
discovered endpoints.

```bash
./crawler/crawlurl2enum.sh -u https://target.com
./crawler/crawlurl2enum.sh -l urls.txt --keep-raw
./crawler/crawlurl2enum.sh -u https://target.com --no-path-probe
```

Options:
- `-u URL` / `-l FILE` — single target or URL list
- `--keep-raw` — keep raw katana/gospider output (default: deleted after categorization)
- `--no-path-probe` — skip common path probe
- `--path-concurrency N` — parallel probe requests (default 15)
- `--path-timeout N` — per-request timeout in seconds (default 8)

Output: `crawl_report_<timestamp>.txt`.

v3 fixes:
- `extract_category` bug fixed: when a pattern matched every remaining line,
  `grep -ivE` exited 1 (no output), `&& mv` never ran, and the stale pool was
  re-reported by every later bucket. Now: `|| true` before `mv`.
- Console output teed to timestamped report file automatically.

---

# comment2enum.py (v3.1)

Extract and triage hidden HTML comments from web targets.

```bash
python Comments/comment2enum.py https://target.com
python Comments/comment2enum.py -f urls.txt --proxy http://127.0.0.1:8080 -w 8
python Comments/comment2enum.py http://10.129.60.23 --insecure -o engagement42/
python Comments/comment2enum.py -f urls.txt --cookie 'sid=abc; role=admin' --rps 4
python Comments/comment2enum.py -f urls.txt --config engagement.json
```

Options:
- `-f FILE` — URL list (one per line, `#` comments allowed)
- `-o OUTDIR` — output directory (default: `comments_<UTC stamp>/`)
- `-w N` — concurrent workers (default 5, max 512)
- `-t N` — per-request timeout in seconds (default 15)
- `-R N` — retries per target (default 3)
- `--backoff N` — retry backoff base in seconds (default 1)
- `--delay N` — seconds to sleep before each target's first request
- `--rps N` — max request starts per second across all workers (default: unlimited)
- `--max-wait N` — cap for a server-supplied `Retry-After` in seconds (default 60)
- `--max-size N` — response body cap in bytes (default 2000000)
- `--parse-all` — parse bodies even when Content-Type is not HTML/XML (disables the binary skip gate)
- `--proxy URL` — proxy for http+https (also `AD2ENUM_PROXY` / `HTTP(S)_PROXY` env)
- `--insecure` — disable TLS certificate verification
- `--no-redirects` — do not follow redirects
- `-A UA` — override User-Agent
- `-H 'Name: value'` — extra request header (repeatable; CR/LF rejected)
- `--cookie PAIRS` — Cookie header for authenticated scans
- `--config FILE` — JSON file of option defaults
- `-q` / `-v` — quiet / verbose logging

Configuration precedence: **CLI > environment > config file > built-in
defaults**. Environment variables: `COMMENT2ENUM_WORKERS`, `_TIMEOUT`,
`_RETRIES`, `_BACKOFF`, `_DELAY`, `_RPS`, `_MAX_SIZE`, `_PROXY`,
`_USER_AGENT`, `_OUTDIR` (plus `AD2ENUM_PROXY` for `--proxy`).

Config file example (`engagement.json`):

```json
{
  "workers": 8,
  "timeout": 20,
  "rps": 4,
  "proxy": "http://127.0.0.1:8080",
  "cookie": "sid=abc; role=admin",
  "header": ["X-Engagement: acme-2026"]
}
```

(`targets` and `config` are reserved keys — pass URLs and the config path
on the command line.)

Output: `comments_<stamp>/found_comments.json` (machine-readable) and
`comments_<stamp>/found_comments.txt` (human-readable). Exit codes:
`0` = run completed, no failed targets (skips don't fail the run),
`1` = usage/config/IO error, `2` = one or more targets failed,
`3` = missing Python dependency.

Concurrency note: the scanner uses `ThreadPoolExecutor` rather than
asyncio on purpose — `requests` is a blocking library, so threads give
real I/O concurrency without pulling in an async HTTP stack, and socket
waits / lxml parsing release the GIL.

v3 rewrite — what changed versus v2 and why:

| Change | Why |
|--------|-----|
| Retries with exponential backoff + full jitter, honoring `Retry-After` | v2 had none: a single 429/502 from a WAF or flaky CDN lost the target |
| Proxy support (`--proxy` or standard env vars) | Route traffic through Burp/Caido/ZAP for verification |
| TLS verification ON by default; `--insecure` opts out | v2 forced `verify=False` globally and silenced warnings |
| Response body size cap (`--max-size`) | Bounds memory on hostile pages |
| URL normalization + validation | Bare hostnames get `https://`; junk skipped with warning instead of `MissingSchema` per target |
| HTTP status recorded; 4xx/5xx are failures | v2 reported `ok` with 0 comments for error pages |
| Thread-local sessions | `requests.Session` is not documented as safe to share across concurrent threads |
| Per-target exception isolation | One broken target can never kill the whole run |
| Structured logging to stderr | v2 used bare `print` |
| JSON + text reports in timestamped output directory | v2 overwrote `found_comments.json` in cwd on every run |
| Meaningful exit codes | Scriptable in pipelines |
| Keyword triage (credentials, TODO, internal IPs, emails, URLs, debug markers) | Flags interesting comments without manual reading |
| Type hints, dataclass config, unit tests (no network) | Maintainability |

v3.1 hardening — what changed versus v3.0 and why:

| Change | Why |
|--------|-----|
| Body reads via public `resp.iter_content()` instead of semi-private `resp.raw.read()`, with mid-body failures inside the retry loop | Raw reads raise *unwrapped* urllib3 errors (`ProtocolError`, `ReadTimeoutError`) that are not `requests.RequestException`, so a connection drop mid-download bypassed retries and was misreported as a permanent `internal` error |
| Content-Type gate (`--parse-all` to disable) | Binary bodies (PDF, images, archives) were fed to BeautifulSoup: wasted CPU and false triage hits from byte noise; skips are reported as `skip`, not `fail` |
| `Retry-After` capped by `--max-wait` (default 60s) | A buggy/hostile `Retry-After: 86400` could park a worker for a day |
| Global `--rps` token-bucket throttle | `--delay` only paused each target's *first* request; a big list could still burst hundreds of req/s at a WAF |
| `-H/--header` + `--cookie` with RFC 7230 token and CR/LF validation | Authenticated scanning is a real engagement need; validation blocks request-line smuggling through config/wrappers |
| JSON `--config` file + `COMMENT2ENUM_*` env vars (CLI > env > config > defaults) | Reproducible per-engagement settings without giant command lines |
| Missing `beautifulsoup4` exits cleanly with code 3 | v3.0 crashed with a raw `ImportError` traceback |
| Session registry + `close()`, `[i/n]` progress logs, second-Ctrl+C-safe partial results | Resource cleanup and trustworthy long-run reporting |
| Report fields `final_url`, `content_type`, `truncated`, `skipped` counter | Post-redirect truth, skip auditing, truncation visibility |
| Usage errors exit 1 (custom argparse `error()`) | argparse's default exit 2 collided with "scan had failed targets" |
| Dedup by canonical key (`a.test` == `a.test/` == `A.test`), fragment stripping, streamed target files | No duplicate scans; O(1) result bookkeeping; constant memory on huge lists |
| Test suite grown 37 → 82 (no network) | Covers retry, gate, rate limit, config precedence, injection rejection, exit codes |
