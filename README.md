# CORSbuster

CORS misconfiguration scanner that actually checks if a vulnerability is exploitable before flagging it.

Most CORS scanners see a reflected `Origin` header and immediately scream "VULNERABLE!" — but that's usually a false positive. If there's no `Access-Control-Allow-Credentials: true`, or if auth is token-based instead of cookies, the browser won't let an attacker do anything with it.

CORSbuster runs 12 different CORS checks, then puts each finding through a 3-stage verification pipeline: detect → verify credentials → check if the response actually contains sensitive data. Only then does it classify severity.

## Quick demo

```
╭──────────────────────────────────────────────────────────────────────╮
│ CORSbuster v1.1.0 — CORS Misconfiguration Scanner                  │
│   Targets: 1 | Threads: 3 | Timeout: 10s | STEALTH MODE            │
╰──────────────────────────────────────────────────────────────────────╯

 [!!!] Reflected Origin | https://target.com/api/users/1
       Origin: https://evil.com → ACAO: https://evil.com
       Credentials: true | Sensitive data: email, user_data | EXPLOITABLE

 [!]   Null Origin | https://target.com/api/users/1
       Origin: null → ACAO: null
       Credentials: true | EXPLOITABLE

 [i]   Wildcard ACAO | https://target.com/api/users/1
       Credentials: false

  Scan complete in 28.0s | Targets: 1 | Checks: 12
  Findings: 7 CRITICAL 1 HIGH 2 MEDIUM 1 LOW
```

That last one (`Wildcard ACAO`) — other tools flag it as vulnerable. We don't, because there's no credentials header. Browser won't send cookies. Not exploitable.

## Install

```bash
# one-liner
curl -sSL https://raw.githubusercontent.com/CyberWarrior9/corsbuster/main/install.sh | bash

# or manually
git clone https://github.com/CyberWarrior9/corsbuster.git
cd corsbuster
pip install -e .
```

The installer checks what dependencies you already have and only installs what's missing.

## Usage

```bash
# basic scan
corsbuster -u https://target.com/api/endpoint

# scan with your session cookie (needed to test authenticated endpoints)
corsbuster -u https://target.com/api/me -H "Cookie: session=abc123"

# stealth mode — slow but won't get your IP blocked
corsbuster -u https://target.com --stealth

# bruteforce directories first, then CORS scan everything found
corsbuster -u https://target.com -b --stealth

# discover common API paths (/api/user, /graphql, etc) and test each
corsbuster -u https://target.com --discover

# crawl the site, pull endpoints from HTML + JS files, test each
corsbuster -u https://target.com -c --depth 3

# pipe URLs from other tools
waybackurls target.com | corsbuster
subfinder -d target.com | httpx | corsbuster --poc
cat urls.txt | corsbuster -o report.json

# go all in
corsbuster -u https://target.com -b --discover -c --stealth --poc -o report.json

# silent mode — just exploitable findings, tab-separated (for scripting)
corsbuster -u https://target.com -s

# through burp proxy
corsbuster -u https://target.com -x http://127.0.0.1:8080
```

## What it checks

12 CORS checks in total:

1. **Reflected Origin** — does the server just echo back whatever `Origin` you send?
2. **Null Origin** — does it accept `Origin: null`? (exploitable via sandboxed iframes)
3. **Pre-domain Bypass** — does `evilexample.com` pass the check?
4. **Post-domain Bypass** — does `example.com.evil.com` pass?
5. **Subdomain Wildcard** — does `evil.example.com` get through?
6. **Unescaped Dot** — regex dot not escaped, so `exampleXcom` works
7. **Special Characters** — backtick, underscore and other chars that break parsers
8. **HTTP Origin Trust** — HTTPS site trusts HTTP origins (MITM risk)
9. **Third-party Origins** — trusts github.io, netlify.app, etc
10. **Wildcard ACAO** — `Access-Control-Allow-Origin: *`
11. **Substring Match** — partial domain matching
12. **Include Match** — domain as substring gets accepted

## How it avoids false positives

This is the main thing that makes CORSbuster different.

**Stage 1 — Detection:** Send crafted `Origin` headers. Before that, send a baseline request *without* any Origin to see what the default ACAO looks like. If a reflected origin matches the baseline, it's static config, not a vulnerability. Also sends a second different origin to confirm dynamic reflection.

**Stage 2 — Credential check:** No `Access-Control-Allow-Credentials: true`? Then the browser won't send cookies cross-origin. Max severity = INFO. Done.

**Stage 3 — Impact assessment:** If credentials ARE allowed, we scan the response body for sensitive stuff — emails, API keys, JWTs, password fields, PII patterns. We also check HOW the user is authenticated: cookie-based auth is exploitable (browsers auto-send cookies), but Bearer token auth is NOT (browsers don't auto-send `Authorization` headers cross-origin).

Only when all three stages confirm real exploitability do we flag it as CRITICAL and generate a PoC.

### Severity levels

```
CRITICAL — attacker can steal authenticated data right now
HIGH     — credentials present, data likely sensitive in other contexts
MEDIUM   — needs a second vuln to chain (subdomain XSS, etc)
LOW      — needs MITM or browser blocks it
INFO     — misconfigured but not exploitable
```

## Stealth mode

Real targets have WAFs. Running hundreds of requests at max threads with a scanner User-Agent will get you blocked instantly.

`--stealth` fixes that:
- Uses a real Chrome User-Agent
- Drops to 3 concurrent threads
- Adds random delays (0.5-3s) between requests
- Auto-detects 429 rate limiting and backs off exponentially

```bash
# this will probably get you blocked
corsbuster -u https://target.com -b

# this won't
corsbuster -u https://target.com -b --stealth
```

Even without `--stealth`, the default User-Agent is a real browser string (not a scanner fingerprint).

## Directory bruteforce

`-b` tests ~800 common paths against the target. If you give it a URL with a path like `https://target.com/app/api`, it bruteforces BOTH:

- `https://target.com/` (base domain)
- `https://target.com/app/api/` (your path)

Then combines all found endpoints and runs CORS checks on everything.

Covers common API routes, admin panels, config files, framework-specific paths (WordPress, Laravel, Django, Spring, etc), sensitive files, and auth endpoints.

Accepts 200, 301/302, and 403 as "endpoint exists" — because CORS headers sometimes leak even on forbidden endpoints.

## Output

- **Terminal** — color-coded findings as they come in
- **JSON** (`-o report.json`) — structured report
- **HTML** (`--html-report report.html`) — standalone dark-themed report you can share
- **PoC HTML** (`--poc`) — working exploit file per vulnerability. For null origin vulns it uses the sandboxed iframe technique
- **Silent** (`-s`) — tab-separated `URL\tSEVERITY\tCHECK`, for piping into other tools

## Exit codes

- `0` — nothing critical
- `2` — CRITICAL or HIGH findings detected (useful for CI/CD)

## Requirements

Python 3.8+ with aiohttp, rich, tldextract (installed automatically).

## Disclaimer

For authorized testing only. Get permission before scanning anything you don't own.

## License

MIT
