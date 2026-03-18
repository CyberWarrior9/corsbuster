"""Stage 2+3: Credential verification, sensitive data detection, exploitability classification."""

import re

from . import AnalysisResult, CheckName, CORSCheckResult, Severity
from .poc import generate_poc_html

# ── Sensitive Data Detection Patterns ─────────────────────────────────

SENSITIVE_PATTERNS = {
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "api_key": re.compile(r'(?i)(?:api[_-]?key|apikey|api_secret|secret_key)["\s:=]+["\']?[a-zA-Z0-9_\-]{16,}'),
    "jwt_token": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+'),
    "aws_key": re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'),
    "private_key": re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
    "password_field": re.compile(r'(?i)"(?:password|passwd|pwd|secret|credential)"\s*:\s*"[^"]+"'),
    "credit_card": re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
    "internal_ip": re.compile(r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'),
}

SENSITIVE_JSON_FIELDS = re.compile(
    r'(?i)"(?:password|secret|token|api_key|access_token|refresh_token|'
    r'session_id|csrf|ssn|social_security|credit_card|card_number|'
    r'account_number|routing_number|private_key)"\s*:'
)

USER_DATA_FIELDS = re.compile(
    r'(?i)"(?:username|user_name|user_id|email|phone|address|'
    r'first_?name|last_?name|date_of_birth|dob|role|admin|'
    r'balance|salary|bank)"\s*:\s*"[^"]+'
)


def detect_sensitive_data(body: str) -> tuple:
    """Scan response body for sensitive data patterns.

    Returns (has_sensitive: bool, matched_types: list[str]).
    """
    if not body:
        return False, []

    # Limit scan to first 50KB
    body = body[:51200]
    matched = []

    for name, pattern in SENSITIVE_PATTERNS.items():
        if pattern.search(body):
            matched.append(name)

    if SENSITIVE_JSON_FIELDS.search(body):
        matched.append("sensitive_json_field")

    if USER_DATA_FIELDS.search(body):
        matched.append("user_data")

    return bool(matched), matched


def detect_auth_mechanism(request_headers: dict, response_headers: dict) -> str:
    """Determine authentication mechanism.

    Returns: 'cookie', 'header', 'none', or 'unknown'.
    """
    has_cookie = any(
        k.lower() == "cookie" for k in request_headers
    )
    has_set_cookie = "set-cookie" in response_headers

    has_auth_header = any(
        k.lower() == "authorization" for k in request_headers
    )

    if has_cookie or has_set_cookie:
        return "cookie"
    if has_auth_header:
        return "header"

    return "unknown"


def classify_severity(
    check_result: CORSCheckResult,
    credentials_allowed: bool,
    has_sensitive_data: bool,
    auth_mechanism: str,
    baseline_acao: str,
) -> tuple:
    """The exploitability decision tree.

    Returns (Severity, exploitable: bool, explanation: str).
    """
    # Step 1: Not reflected at all
    if not check_result.is_reflected:
        return Severity.INFO, False, "Origin not reflected in ACAO header"

    check = check_result.check_name
    acao = check_result.acao_received or ""

    # Step 2: Wildcard check
    if acao.strip() == "*":
        if credentials_allowed:
            return (
                Severity.LOW, False,
                "ACAO:* with ACAC:true — browsers reject this combination per CORS spec. "
                "Server is misconfigured but not exploitable."
            )
        return (
            Severity.INFO, False,
            "ACAO:* without credentials — public access only, not exploitable for authenticated data."
        )

    # Step 3: Static ACAO (same as baseline without Origin)
    if baseline_acao and acao.strip().lower() == baseline_acao.strip().lower():
        return (
            Severity.INFO, False,
            f"Static ACAO (same as baseline: {baseline_acao}). Not dynamic reflection."
        )

    # Step 4: No credentials
    if not credentials_allowed:
        return (
            Severity.INFO, False,
            "Origin reflected but Access-Control-Allow-Credentials is not 'true'. "
            "Browsers won't forward cookies — not exploitable for authenticated data."
        )

    # Step 5: Credentials ARE allowed — check auth mechanism
    if auth_mechanism == "header":
        return (
            Severity.LOW, False,
            "Origin reflected with credentials, but authentication uses Authorization header "
            "(Bearer token). Browsers don't auto-forward custom headers cross-origin — "
            "not exploitable via CORS."
        )

    # Step 6: Cookie-based or unknown auth + credentials → classify by check type
    bypass_checks = {
        CheckName.REFLECTED_ORIGIN,
        CheckName.PRE_DOMAIN_BYPASS,
        CheckName.POST_DOMAIN_BYPASS,
        CheckName.SUBSTRING_MATCH,
        CheckName.INCLUDE_MATCH,
        CheckName.UNESCAPED_DOT,
        CheckName.SPECIAL_CHARS,
    }

    if check in bypass_checks:
        if has_sensitive_data:
            return (
                Severity.CRITICAL, True,
                f"{check.value}: Origin bypass with credentials and sensitive data confirmed. "
                f"Attacker can register a domain and steal authenticated user data."
            )
        return (
            Severity.HIGH, True,
            f"{check.value}: Origin bypass with credentials. Response may contain "
            f"sensitive data in other contexts (different user, different parameters)."
        )

    if check == CheckName.NULL_ORIGIN:
        if has_sensitive_data:
            return (
                Severity.HIGH, True,
                "Null origin accepted with credentials and sensitive data. "
                "Exploitable via sandboxed iframe (data: URI, iframe sandbox)."
            )
        return (
            Severity.MEDIUM, True,
            "Null origin accepted with credentials. Exploitable via sandboxed iframe "
            "but no sensitive data detected in current response."
        )

    if check == CheckName.SUBDOMAIN_WILDCARD:
        return (
            Severity.MEDIUM, True,
            "Any subdomain trusted with credentials. Requires XSS on any subdomain "
            "to exploit (e.g., evil.target.com). Check for subdomain takeover opportunities."
        )

    if check == CheckName.HTTP_ORIGIN_TRUST:
        return (
            Severity.LOW, True,
            "HTTPS endpoint trusts HTTP origin with credentials. "
            "Requires active MITM (man-in-the-middle) to exploit."
        )

    if check == CheckName.THIRD_PARTY_ORIGINS:
        origin = check_result.origin_sent
        return (
            Severity.MEDIUM, True,
            f"Third-party hosting platform ({origin}) trusted with credentials. "
            f"Attacker can host exploit on this platform."
        )

    # Fallback
    return Severity.INFO, False, f"{check.value}: Misconfiguration detected but not clearly exploitable."


def analyze_finding(
    check_result: CORSCheckResult,
    baseline: dict,
    request_headers: dict,
) -> AnalysisResult:
    """Full Stage 2+3 analysis pipeline for a single check result."""

    # Stage 2: Credential verification
    acac = check_result.acac_received or ""
    credentials_allowed = acac.strip().lower() == "true"

    # Stage 3: Impact assessment
    has_sensitive, sensitive_types = detect_sensitive_data(check_result.response_body)
    auth_mechanism = detect_auth_mechanism(request_headers, check_result.raw_headers)

    baseline_acao = baseline.get("acao")

    severity, exploitable, explanation = classify_severity(
        check_result=check_result,
        credentials_allowed=credentials_allowed,
        has_sensitive_data=has_sensitive,
        auth_mechanism=auth_mechanism,
        baseline_acao=baseline_acao,
    )

    # Generate PoC if exploitable
    poc_html = ""
    if exploitable:
        poc_html = generate_poc_html(check_result, severity)

    return AnalysisResult(
        check_result=check_result,
        credentials_allowed=credentials_allowed,
        has_sensitive_data=has_sensitive,
        sensitive_data_types=sensitive_types,
        auth_mechanism=auth_mechanism,
        severity=severity,
        exploitable=exploitable,
        explanation=explanation,
        poc_html=poc_html,
    )
