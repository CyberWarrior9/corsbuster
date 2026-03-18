"""Entry point for `python -m corsbuster`."""

import asyncio
import sys

from . import ScanTarget
from .cli import parse_args
from .poc import save_poc_file
from .reporter import Reporter
from .scanner import CORSScanner


def _run_discovery(config, console):
    """Run endpoint discovery and add found URLs to targets."""
    from .discover import discover_endpoints

    base_urls = set()
    for target in config.targets:
        from urllib.parse import urlparse
        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        base_urls.add(base)

    discovered = []

    for base_url in base_urls:
        console.print(f"  [cyan][*] Discovering endpoints on {base_url}...[/cyan]")

        found = asyncio.run(discover_endpoints(
            base_url=base_url,
            timeout=min(config.timeout, 5),
            proxy=config.proxy,
            verify_ssl=config.verify_ssl,
            threads=20,
            on_found=lambda url: console.print(f"    [green][+][/green] {url}"),
        ))
        discovered.extend(found)

    if discovered:
        console.print(f"  [green][+] Discovered {len(discovered)} endpoints[/green]\n")
        existing = {t.url for t in config.targets}
        for url in discovered:
            if url not in existing:
                config.targets.append(ScanTarget(url=url, custom_headers=config.custom_headers))
                existing.add(url)
    else:
        console.print("  [yellow][-] No endpoints discovered[/yellow]\n")


def _run_crawler(config, console):
    """Run web crawler and add found URLs to targets."""
    from .crawler import Crawler

    base_urls = set()
    for target in config.targets:
        from urllib.parse import urlparse
        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        base_urls.add(base)

    crawled = []

    for base_url in base_urls:
        console.print(
            f"  [cyan][*] Crawling {base_url} (depth: {config.crawl_depth})...[/cyan]"
        )

        crawler = Crawler(
            base_url=base_url,
            max_depth=config.crawl_depth,
            timeout=config.timeout,
            proxy=config.proxy,
            verify_ssl=config.verify_ssl,
            threads=config.threads,
        )

        found = asyncio.run(crawler.crawl())
        crawled.extend(found)

        console.print(
            f"    [dim]Pages visited: {len(crawler.visited)} | "
            f"JS files parsed: {len(crawler.js_urls)}[/dim]"
        )

    if crawled:
        console.print(f"  [green][+] Crawled {len(crawled)} URLs[/green]\n")
        existing = {t.url for t in config.targets}
        for url in crawled:
            if url not in existing:
                config.targets.append(ScanTarget(url=url, custom_headers=config.custom_headers))
                existing.add(url)
    else:
        console.print("  [yellow][-] No URLs found by crawler[/yellow]\n")


def _run_bruteforce(config, console):
    """Run directory bruteforce and add found URLs to targets."""
    from urllib.parse import urlparse

    from .bruteforce import bruteforce_paths

    # Build list of bases to bruteforce:
    # For each target URL, create TWO bases:
    #   1. scheme://netloc (base domain)
    #   2. scheme://netloc/path (user's path, if it has one)
    bases = set()
    for target in config.targets:
        parsed = urlparse(target.url)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"
        bases.add(base_domain)

        # If the URL has a path beyond /, add it as second base
        if parsed.path and parsed.path != "/":
            full_path_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            bases.add(full_path_base)

    discovered = []
    total_bases = len(bases)

    for i, base_url in enumerate(sorted(bases), 1):
        console.print(
            f"  [cyan][*] Bruteforcing {base_url} ({i}/{total_bases})...[/cyan]"
        )

        def on_progress(checked, total, found):
            console.print(
                f"\r    [dim]{checked}/{total} checked | {found} found[/dim]",
                end="",
            )

        def on_found(url, status):
            status_label = "403" if status == 403 else str(status)
            console.print(f"    [green][+][/green] [{status_label}] {url}")

        found = asyncio.run(bruteforce_paths(
            base_url=base_url,
            timeout=min(config.timeout, 5),
            proxy=config.proxy,
            verify_ssl=config.verify_ssl,
            threads=config.threads,
            stealth=config.stealth,
            on_found=on_found,
            on_progress=on_progress,
        ))
        discovered.extend(found)
        console.print()  # newline after progress

    if discovered:
        # Deduplicate
        unique = list(dict.fromkeys(discovered))
        console.print(
            f"  [green][+] Bruteforce complete: {len(unique)} endpoints found "
            f"(from {total_bases} base{'s' if total_bases > 1 else ''})[/green]\n"
        )
        existing = {t.url for t in config.targets}
        for url in unique:
            if url not in existing:
                config.targets.append(ScanTarget(url=url, custom_headers=config.custom_headers))
                existing.add(url)
    else:
        console.print("  [yellow][-] No endpoints found via bruteforce[/yellow]\n")


def _run_wayback(config, console):
    """Pull historical URLs from Wayback Machine."""
    from urllib.parse import urlparse

    from .wayback import fetch_wayback_urls

    domains = set()
    for target in config.targets:
        parsed = urlparse(target.url)
        domains.add(parsed.netloc)

    found_all = []
    for domain in sorted(domains):
        console.print(f"  [cyan][*] Fetching Wayback Machine URLs for {domain}...[/cyan]")
        found = asyncio.run(fetch_wayback_urls(
            domain=domain,
            on_found=lambda url: console.print(f"    [green][+][/green] {url}"),
        ))
        found_all.extend(found)

    if found_all:
        console.print(f"  [green][+] Wayback: {len(found_all)} historical endpoints found[/green]\n")
        existing = {t.url for t in config.targets}
        for url in found_all:
            if url not in existing:
                config.targets.append(ScanTarget(url=url, custom_headers=config.custom_headers))
                existing.add(url)
    else:
        console.print("  [yellow][-] No Wayback URLs found[/yellow]\n")


def _run_subdomains(config, console):
    """Enumerate subdomains via crt.sh."""
    from urllib.parse import urlparse

    from .subdomains import enumerate_subdomains

    domains = set()
    for target in config.targets:
        parsed = urlparse(target.url)
        # get the root domain (strip subdomains like www)
        import tldextract
        ext = tldextract.extract(target.url)
        domains.add(ext.registered_domain)

    found_all = []
    for domain in sorted(domains):
        console.print(f"  [cyan][*] Enumerating subdomains for {domain}...[/cyan]")
        found = asyncio.run(enumerate_subdomains(
            domain=domain,
            verify_ssl=config.verify_ssl,
            on_found=lambda url: console.print(f"    [green][+][/green] {url}"),
        ))
        found_all.extend(found)

    if found_all:
        console.print(f"  [green][+] Found {len(found_all)} alive subdomains[/green]\n")
        existing = {t.url for t in config.targets}
        for url in found_all:
            if url not in existing:
                config.targets.append(ScanTarget(url=url, custom_headers=config.custom_headers))
                existing.add(url)
    else:
        console.print("  [yellow][-] No subdomains found[/yellow]\n")


def _apply_scope(config, console):
    """Filter targets based on --scope and --exclude."""
    from fnmatch import fnmatch

    if not config.scope and not config.exclude:
        return

    before = len(config.targets)
    filtered = []

    for target in config.targets:
        url = target.url

        # scope whitelist
        if config.scope:
            if not any(s in url for s in config.scope):
                continue

        # exclude blacklist
        if config.exclude:
            if any(fnmatch(url, pat) or fnmatch(url.split("?")[0], pat) for pat in config.exclude):
                continue

        filtered.append(target)

    config.targets = filtered
    removed = before - len(filtered)
    if removed and not config.silent:
        console.print(f"  [dim]Scope filter: {removed} URLs excluded, {len(filtered)} remaining[/dim]\n")


def main():
    config = parse_args()
    reporter = Reporter()

    if not config.silent:
        reporter.print_banner(config)

    # Resume: load checkpoint and skip already-scanned URLs
    skipped = set()
    if config.resume:
        from .checkpoint import load_checkpoint
        skipped = load_checkpoint(config)
        if skipped and not config.silent:
            reporter.console.print(f"  [cyan][*] Resuming: {len(skipped)} URLs already scanned[/cyan]\n")

    # Run subdomain enumeration
    if config.subdomains:
        _run_subdomains(config, reporter.console)

    # Run wayback
    if config.wayback:
        _run_wayback(config, reporter.console)

    # Run discovery
    if config.discover:
        _run_discovery(config, reporter.console)

    # Run bruteforce
    if config.bruteforce:
        _run_bruteforce(config, reporter.console)

    # Run crawler
    if config.crawl:
        _run_crawler(config, reporter.console)

    # Apply scope filtering (after all discovery phases)
    _apply_scope(config, reporter.console)

    # Remove already-scanned URLs (resume mode)
    if skipped:
        config.targets = [t for t in config.targets if t.url not in skipped]

    if not config.silent:
        reporter.console.print(
            f"  [dim]Scanning {len(config.targets)} target(s)...[/dim]\n"
        )

    if not config.targets:
        if not config.silent:
            reporter.console.print("  [yellow]No targets to scan.[/yellow]")
        sys.exit(0)

    # Run CORS scan
    scanner = CORSScanner(config)
    try:
        report = asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        reporter.console.print("\n[yellow]Scan interrupted. Use --resume to continue.[/yellow]")
        sys.exit(1)

    # Clean up checkpoint on successful completion
    if config.resume:
        from .checkpoint import delete_checkpoint
        delete_checkpoint()

    if config.silent:
        # Silent mode — only print exploitable URLs
        for finding in report.findings:
            if finding.exploitable:
                check = finding.check_result
                print(f"{check.url}\t{finding.severity.value}\t{check.check_name.value}")
    else:
        # Normal output
        for finding in report.findings:
            if finding.severity.value != "INFO" or config.verbose:
                reporter.print_finding(finding)

        reporter.print_summary_table(report)

    # Save PoC files
    if config.generate_poc:
        poc_count = 0
        for finding in report.findings:
            if finding.exploitable and finding.poc_html:
                filepath = save_poc_file(finding)
                if filepath:
                    if not config.silent:
                        reporter.console.print(f"  [green]PoC saved:[/green] {filepath}")
                    poc_count += 1
        if poc_count and not config.silent:
            reporter.console.print(f"  [green]{poc_count} PoC file(s) generated.[/green]")

    # Export reports
    if config.output_json:
        reporter.export_json(report, config.output_json)
        if not config.silent:
            reporter.console.print(f"  [green]JSON report saved:[/green] {config.output_json}")

    if config.output_html:
        reporter.generate_html_report(report, config.output_html)
        if not config.silent:
            reporter.console.print(f"  [green]HTML report saved:[/green] {config.output_html}")

    # Exit code: 2 if critical/high findings (useful for CI/CD)
    if report.critical_count > 0 or report.high_count > 0:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
