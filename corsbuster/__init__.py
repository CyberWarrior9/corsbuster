"""CORSbuster - CORS Misconfiguration Scanner with Exploitability Verification."""

__version__ = "1.1.0"

# Default User-Agent that looks like a real browser
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
__author__ = "CyberWarrior9"

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckName(Enum):
    REFLECTED_ORIGIN = "Reflected Origin"
    NULL_ORIGIN = "Null Origin"
    PRE_DOMAIN_BYPASS = "Pre-domain Bypass"
    POST_DOMAIN_BYPASS = "Post-domain Bypass"
    SUBDOMAIN_WILDCARD = "Subdomain Wildcard"
    UNESCAPED_DOT = "Unescaped Dot"
    SPECIAL_CHARS = "Special Characters"
    HTTP_ORIGIN_TRUST = "HTTP Origin Trust"
    THIRD_PARTY_ORIGINS = "Third-party Origins"
    WILDCARD = "Wildcard ACAO"
    SUBSTRING_MATCH = "Substring Match"
    INCLUDE_MATCH = "Include Match"


@dataclass
class CORSCheckResult:
    """Result from a single CORS check (Stage 1)."""
    check_name: CheckName
    url: str
    origin_sent: str
    acao_received: Optional[str] = None
    acac_received: Optional[str] = None
    is_reflected: bool = False
    raw_headers: dict = field(default_factory=dict)
    response_body: str = ""
    status_code: int = 0


@dataclass
class AnalysisResult:
    """Result from exploitability analysis (Stage 2+3)."""
    check_result: CORSCheckResult
    credentials_allowed: bool = False
    has_sensitive_data: bool = False
    sensitive_data_types: list = field(default_factory=list)
    auth_mechanism: str = "unknown"  # "cookie", "header", "none", "unknown"
    severity: Severity = Severity.INFO
    exploitable: bool = False
    explanation: str = ""
    poc_html: str = ""


@dataclass
class ScanTarget:
    """A URL to scan with optional custom headers."""
    url: str
    custom_headers: dict = field(default_factory=dict)


@dataclass
class ScanConfig:
    """Global scan configuration from CLI args."""
    targets: list = field(default_factory=list)
    threads: int = 10
    timeout: int = 10
    delay: float = 0.0
    proxy: Optional[str] = None
    verify_ssl: bool = True
    generate_poc: bool = False
    output_json: Optional[str] = None
    output_html: Optional[str] = None
    verbose: bool = False
    silent: bool = False
    discover: bool = False
    crawl: bool = False
    crawl_depth: int = 3
    bruteforce: bool = False
    stealth: bool = False
    custom_headers: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    """Final report with all findings."""
    targets_scanned: int = 0
    checks_performed: int = 0
    findings: list = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)
