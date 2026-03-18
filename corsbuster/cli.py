"""CLI argument parsing for CORSbuster."""

import argparse
import sys

from . import ScanConfig, ScanTarget, __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corsbuster",
        description="CORSbuster - CORS Misconfiguration Scanner with Exploitability Verification",
        epilog=(
            "Examples:\n"
            "  corsbuster -u https://target.com/api/me -H 'Cookie: session=abc' --poc\n"
            "  corsbuster -u https://target.com --discover\n"
            "  corsbuster -u https://target.com/api -b\n"
            "  corsbuster -u https://target.com -c --depth 3\n"
            "  echo 'https://target.com/api/user' | corsbuster\n"
            "  waybackurls target.com | corsbuster --poc\n"
            "  corsbuster -u https://target.com -b --stealth\n"
            "  corsbuster -u target.com --subdomains --wayback -b --methods --stealth"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target
    target = parser.add_argument_group("Target")
    target.add_argument("-u", "--url", help="Single target URL to scan")
    target.add_argument("-l", "--list", dest="url_list", help="File containing URLs (one per line)")

    # Discovery
    discovery = parser.add_argument_group("Discovery")
    discovery.add_argument(
        "--discover", action="store_true",
        help="Discover common API endpoints on target and test each for CORS"
    )
    discovery.add_argument(
        "-c", "--crawl", action="store_true",
        help="Crawl the target website, extract URLs from HTML + JS, test each for CORS"
    )
    discovery.add_argument(
        "-b", "--bruteforce", action="store_true",
        help="Directory bruteforce with built-in 800+ path wordlist, then CORS scan found endpoints"
    )
    discovery.add_argument(
        "--wayback", action="store_true",
        help="Fetch historical endpoints from Wayback Machine"
    )
    discovery.add_argument(
        "--subdomains", action="store_true",
        help="Enumerate subdomains via crt.sh certificate transparency"
    )
    discovery.add_argument(
        "--methods", action="store_true",
        help="Also test CORS on POST, PUT, DELETE, PATCH (not just GET)"
    )
    discovery.add_argument(
        "--depth", type=int, default=3,
        help="Crawl depth (default: 3, used with -c/--crawl)"
    )

    # Scope
    scope_group = parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--scope", dest="scope", action="append", default=[],
        help="Only scan URLs containing this domain (repeatable)"
    )
    scope_group.add_argument(
        "--exclude", dest="exclude", action="append", default=[],
        help="Skip URLs matching this pattern (repeatable, supports wildcards)"
    )

    # Session
    session_group = parser.add_argument_group("Session")
    session_group.add_argument(
        "--resume", action="store_true",
        help="Resume a previously interrupted scan from checkpoint"
    )

    # Authentication
    auth = parser.add_argument_group("Authentication")
    auth.add_argument(
        "-H", "--header", dest="headers", action="append", default=[],
        help="Custom header (repeatable). Format: 'Name: Value'"
    )

    # Output
    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output", dest="output_json", help="Save JSON report to file")
    output.add_argument("--html-report", dest="output_html", help="Save HTML report to file")
    output.add_argument("--poc", action="store_true", help="Generate PoC HTML files for exploitable findings")
    output.add_argument("-v", "--verbose", action="store_true", help="Show all checks (not just findings)")
    output.add_argument(
        "-s", "--silent", action="store_true",
        help="Silent mode — only output exploitable findings (for piping)"
    )

    # Network
    network = parser.add_argument_group("Network")
    network.add_argument("-x", "--proxy", help="HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)")
    network.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    network.add_argument("--threads", type=int, default=10, help="Concurrent targets (default: 10)")
    network.add_argument("--delay", type=float, default=0.0, help="Delay between checks per target in seconds")
    network.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    network.add_argument(
        "--stealth", action="store_true",
        help="Stealth mode — realistic User-Agent, low threads (3), random delays (1-3s), auto-backoff on 429/403"
    )

    parser.add_argument("--version", action="version", version=f"CORSbuster v{__version__}")

    return parser


def _parse_headers(header_strings: list) -> dict:
    """Convert ['Cookie: x=y', 'Authorization: Bearer z'] into a dict."""
    headers = {}
    for h in header_strings:
        if ":" not in h:
            print(f"[!] Invalid header format (expected 'Name: Value'): {h}", file=sys.stderr)
            continue
        name, value = h.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def _load_url_list(filepath: str) -> list:
    """Read URLs from file, one per line."""
    try:
        with open(filepath) as f:
            urls = []
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
            return urls
    except FileNotFoundError:
        print(f"[!] URL list file not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[!] Cannot read file: {filepath}", file=sys.stderr)
        sys.exit(1)


def _read_stdin() -> list:
    """Read URLs from stdin (pipe support)."""
    urls = []
    for line in sys.stdin:
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def parse_args(argv: list = None) -> ScanConfig:
    """Parse command-line arguments into a ScanConfig."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Check if stdin has data (pipe mode)
    has_stdin = not sys.stdin.isatty()

    if not args.url and not args.url_list and not has_stdin:
        parser.error("No input provided. Use -u URL, -l FILE, or pipe URLs via stdin")

    custom_headers = _parse_headers(args.headers)

    # Build target list
    urls = []
    if args.url:
        urls.append(_normalize_url(args.url))
    if args.url_list:
        urls.extend(_normalize_url(u) for u in _load_url_list(args.url_list))
    if has_stdin:
        urls.extend(_normalize_url(u) for u in _read_stdin())

    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)
    urls = unique_urls

    if not urls:
        parser.error("No valid URLs provided")

    targets = [ScanTarget(url=url, custom_headers=custom_headers) for url in urls]

    # Stealth mode overrides
    stealth = args.stealth
    threads = args.threads
    delay = args.delay

    if stealth:
        # Override only if user didn't explicitly set these
        if args.threads == 10:  # default
            threads = 3
        if args.delay == 0.0:  # default
            delay = 1.5  # base delay, actual will be randomized 1-3s

    return ScanConfig(
        targets=targets,
        threads=threads,
        timeout=args.timeout,
        delay=delay,
        proxy=args.proxy,
        verify_ssl=not args.no_verify_ssl,
        generate_poc=args.poc,
        output_json=args.output_json,
        output_html=args.output_html,
        verbose=args.verbose,
        silent=args.silent,
        discover=args.discover,
        crawl=args.crawl,
        crawl_depth=args.depth,
        bruteforce=args.bruteforce,
        stealth=stealth,
        wayback=args.wayback,
        subdomains=args.subdomains,
        methods=args.methods,
        scope=args.scope,
        exclude=args.exclude,
        resume=args.resume,
        custom_headers=custom_headers,
    )
