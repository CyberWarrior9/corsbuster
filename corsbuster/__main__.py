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


def main():
    config = parse_args()
    reporter = Reporter()

    if not config.silent:
        reporter.print_banner(config)

    # Run discovery if requested
    if config.discover:
        _run_discovery(config, reporter.console)

    # Run bruteforce if requested
    if config.bruteforce:
        _run_bruteforce(config, reporter.console)

    # Run crawler if requested
    if config.crawl:
        _run_crawler(config, reporter.console)

    if not config.silent:
        reporter.console.print(
            f"  [dim]Scanning {len(config.targets)} target(s)...[/dim]\n"
        )

    # Run CORS scan
    scanner = CORSScanner(config)
    try:
        report = asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        reporter.console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(1)

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
