"""Output formatting: terminal table (rich), JSON export, HTML report."""

import json
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import AnalysisResult, ScanConfig, ScanReport, Severity, __version__

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold bright_red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[!!!]",
    Severity.HIGH: "[!!]",
    Severity.MEDIUM: "[!]",
    Severity.LOW: "[-]",
    Severity.INFO: "[i]",
}


class Reporter:
    def __init__(self, console: Console = None):
        self.console = console or Console()

    def print_banner(self, config: ScanConfig):
        banner = Text()
        banner.append("CORSbuster", style="bold red")
        banner.append(f" v{__version__}", style="dim")
        banner.append(" — CORS Misconfiguration Scanner\n", style="")
        banner.append(f"  Targets: {len(config.targets)}", style="cyan")
        banner.append(f" | Threads: {config.threads}", style="cyan")
        banner.append(f" | Timeout: {config.timeout}s", style="cyan")
        if config.proxy:
            banner.append(f" | Proxy: {config.proxy}", style="cyan")
        if config.custom_headers:
            banner.append(f" | Custom headers: {len(config.custom_headers)}", style="cyan")
        if config.stealth:
            banner.append(" | STEALTH MODE", style="bold green")

        self.console.print(Panel(banner, border_style="red"))

    def print_finding(self, analysis: AnalysisResult):
        """Print a single finding in real-time."""
        sev = analysis.severity
        style = SEVERITY_STYLES[sev]
        icon = SEVERITY_ICONS[sev]
        check = analysis.check_result

        line = Text()
        line.append(f" {icon} ", style=style)
        line.append(f"{check.check_name.value}", style=style)
        line.append(f" | {check.url}\n", style="")
        line.append(f"      Origin: {check.origin_sent}", style="dim")
        line.append(f" → ACAO: {check.acao_received or 'None'}\n", style="dim")
        line.append(f"      Credentials: ", style="dim")
        line.append(
            "true" if analysis.credentials_allowed else "false",
            style="green" if analysis.credentials_allowed else "dim",
        )
        if analysis.sensitive_data_types:
            line.append(f" | Sensitive data: {', '.join(analysis.sensitive_data_types)}", style="yellow")
        if analysis.auth_mechanism != "unknown":
            line.append(f" | Auth: {analysis.auth_mechanism}", style="dim")
        if analysis.exploitable:
            line.append(" | EXPLOITABLE", style="bold red")

        self.console.print(line)

    def print_summary_table(self, report: ScanReport):
        """Print final findings table."""
        self.console.print()

        # Filter to only show relevant findings (not INFO in non-verbose mode)
        findings = report.findings

        if not findings:
            self.console.print("[dim]No CORS misconfigurations detected.[/dim]")
            self._print_stats(report)
            return

        table = Table(
            title="Scan Results",
            border_style="bright_black",
            header_style="bold",
            show_lines=True,
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Severity", width=10)
        table.add_column("Check", width=22)
        table.add_column("URL", max_width=45, no_wrap=True)
        table.add_column("ACAO", max_width=30, no_wrap=True)
        table.add_column("Creds", width=5)
        table.add_column("Sensitive Data", max_width=25)
        table.add_column("Exploitable", width=11)

        for i, f in enumerate(findings, 1):
            sev_style = SEVERITY_STYLES[f.severity]
            check = f.check_result

            creds = Text("true", style="green") if f.credentials_allowed else Text("false", style="dim")
            exploitable = Text("YES", style="bold red") if f.exploitable else Text("no", style="dim")
            sensitive = ", ".join(f.sensitive_data_types[:3]) if f.sensitive_data_types else "-"

            table.add_row(
                str(i),
                Text(f.severity.value, style=sev_style),
                check.check_name.value,
                check.url,
                str(check.acao_received or "-"),
                creds,
                sensitive,
                exploitable,
            )

        self.console.print(table)
        self._print_stats(report)

    def _print_stats(self, report: ScanReport):
        stats = Text()
        stats.append(f"\n  Scan complete in {report.duration_seconds}s", style="dim")
        stats.append(f" | Targets: {report.targets_scanned}", style="dim")
        stats.append(f" | Checks: {report.checks_performed}", style="dim")
        stats.append(f" | Findings: ", style="dim")
        if report.critical_count:
            stats.append(f"{report.critical_count} CRITICAL ", style="bold red")
        if report.high_count:
            stats.append(f"{report.high_count} HIGH ", style="bold bright_red")
        if report.medium_count:
            stats.append(f"{report.medium_count} MEDIUM ", style="bold yellow")
        if report.low_count:
            stats.append(f"{report.low_count} LOW ", style="bold blue")
        if report.info_count:
            stats.append(f"{report.info_count} INFO", style="dim")
        if not any([report.critical_count, report.high_count, report.medium_count,
                     report.low_count, report.info_count]):
            stats.append("0", style="dim")
        self.console.print(stats)

    def export_json(self, report: ScanReport, filepath: str):
        """Export findings as JSON."""
        data = {
            "scan_info": {
                "tool": "CORSbuster",
                "version": __version__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "targets_scanned": report.targets_scanned,
                "checks_performed": report.checks_performed,
                "duration_seconds": report.duration_seconds,
            },
            "summary": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "info": report.info_count,
            },
            "findings": [],
        }

        for f in report.findings:
            check = f.check_result
            data["findings"].append({
                "url": check.url,
                "check_name": check.check_name.value,
                "severity": f.severity.value,
                "exploitable": f.exploitable,
                "origin_sent": check.origin_sent,
                "acao_received": check.acao_received,
                "credentials_allowed": f.credentials_allowed,
                "sensitive_data_types": f.sensitive_data_types,
                "auth_mechanism": f.auth_mechanism,
                "explanation": f.explanation,
                "status_code": check.status_code,
            })

        try:
            with open(filepath, "w") as fh:
                json.dump(data, fh, indent=2)
        except OSError as e:
            self.console.print(f"[red]Error writing JSON report: {e}[/red]")

    def generate_html_report(self, report: ScanReport, filepath: str):
        """Generate standalone HTML report."""
        rows = ""
        for f in report.findings:
            check = f.check_result
            sev_color = {
                Severity.CRITICAL: "#ff4444",
                Severity.HIGH: "#ff6b6b",
                Severity.MEDIUM: "#ffd93d",
                Severity.LOW: "#4dabf7",
                Severity.INFO: "#888",
            }.get(f.severity, "#888")

            sensitive = ", ".join(f.sensitive_data_types) if f.sensitive_data_types else "-"
            exploit_badge = '<span class="badge-exploit">EXPLOITABLE</span>' if f.exploitable else "No"

            rows += f"""<tr>
                <td style="color:{sev_color};font-weight:bold">{f.severity.value}</td>
                <td>{_esc(check.check_name.value)}</td>
                <td class="url">{_esc(check.url)}</td>
                <td>{_esc(str(check.acao_received or '-'))}</td>
                <td>{"true" if f.credentials_allowed else "false"}</td>
                <td>{_esc(sensitive)}</td>
                <td>{exploit_badge}</td>
                <td class="explanation">{_esc(f.explanation)}</td>
            </tr>\n"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CORSbuster Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 30px; }}
        h1 {{ color: #ff6b6b; margin-bottom: 5px; }}
        .subtitle {{ color: #888; margin-bottom: 25px; }}
        .stats {{ display: flex; gap: 20px; margin-bottom: 25px; flex-wrap: wrap; }}
        .stat {{ background: #161b22; border: 1px solid #30363d; padding: 12px 20px; border-radius: 6px; }}
        .stat-label {{ color: #888; font-size: 12px; }}
        .stat-value {{ font-size: 22px; font-weight: bold; }}
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff6b6b; }}
        .medium {{ color: #ffd93d; }}
        .low {{ color: #4dabf7; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th {{ background: #161b22; color: #58a6ff; padding: 10px; text-align: left;
              border-bottom: 2px solid #30363d; font-size: 13px; }}
        td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 13px; vertical-align: top; }}
        tr:hover {{ background: #161b22; }}
        .url {{ max-width: 300px; word-break: break-all; }}
        .explanation {{ max-width: 350px; color: #888; font-size: 12px; }}
        .badge-exploit {{ background: #ff4444; color: #fff; padding: 2px 8px;
                          border-radius: 3px; font-size: 11px; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>CORSbuster Report</h1>
    <div class="subtitle">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
        | v{__version__}</div>
    <div class="stats">
        <div class="stat"><div class="stat-label">Targets</div>
            <div class="stat-value">{report.targets_scanned}</div></div>
        <div class="stat"><div class="stat-label">Checks</div>
            <div class="stat-value">{report.checks_performed}</div></div>
        <div class="stat"><div class="stat-label">Duration</div>
            <div class="stat-value">{report.duration_seconds}s</div></div>
        <div class="stat"><div class="stat-label">Critical</div>
            <div class="stat-value critical">{report.critical_count}</div></div>
        <div class="stat"><div class="stat-label">High</div>
            <div class="stat-value high">{report.high_count}</div></div>
        <div class="stat"><div class="stat-label">Medium</div>
            <div class="stat-value medium">{report.medium_count}</div></div>
        <div class="stat"><div class="stat-label">Low</div>
            <div class="stat-value low">{report.low_count}</div></div>
    </div>
    <table>
        <tr>
            <th>Severity</th><th>Check</th><th>URL</th><th>ACAO</th>
            <th>Creds</th><th>Sensitive Data</th><th>Exploitable</th><th>Details</th>
        </tr>
        {rows}
    </table>
</body>
</html>"""

        try:
            with open(filepath, "w") as fh:
                fh.write(html)
        except OSError as e:
            self.console.print(f"[red]Error writing HTML report: {e}[/red]")


def _esc(s: str) -> str:
    """Escape for HTML."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
