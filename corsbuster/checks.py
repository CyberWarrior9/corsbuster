"""CORS checks + baseline + preflight + method-specific testing."""

import asyncio
from urllib.parse import urlparse

import aiohttp
import tldextract

from . import CheckName, CORSCheckResult, DEFAULT_USER_AGENT


async def _send_cors_request(
    session: aiohttp.ClientSession,
    url: str,
    origin: str,
    check_name: CheckName,
    extra_headers: dict = None,
    timeout: int = 10,
    proxy: str = None,
    method: str = "GET",
) -> CORSCheckResult:
    """Send a request with a crafted Origin header and parse CORS response."""
    headers = {"Origin": origin, "User-Agent": DEFAULT_USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        req_method = getattr(session, method.lower(), session.get)
        async with req_method(
            url, headers=headers, timeout=client_timeout,
            proxy=proxy, allow_redirects=True,
        ) as resp:
            body = await resp.text(errors="replace")
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            acao = raw_headers.get("access-control-allow-origin")
            acac = raw_headers.get("access-control-allow-credentials")

            # Determine if origin was reflected
            is_reflected = False
            if acao:
                acao_clean = acao.strip().lower()
                origin_clean = origin.strip().lower()
                if acao_clean == origin_clean or acao_clean == "*":
                    is_reflected = True

            return CORSCheckResult(
                check_name=check_name,
                url=url,
                origin_sent=origin,
                acao_received=acao,
                acac_received=acac,
                is_reflected=is_reflected,
                raw_headers=raw_headers,
                response_body=body[:51200],  # Cap at 50KB
                status_code=resp.status,
            )

    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return CORSCheckResult(
            check_name=check_name,
            url=url,
            origin_sent=origin,
            is_reflected=False,
        )


async def get_baseline(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int = 10,
    proxy: str = None,
    extra_headers: dict = None,
) -> dict:
    """Send request with NO Origin header to record default ACAO."""
    headers = extra_headers or {}
    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(
            url, headers=headers, timeout=client_timeout,
            proxy=proxy, allow_redirects=True,
        ) as resp:
            body = await resp.text(errors="replace")
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "acao": raw_headers.get("access-control-allow-origin"),
                "acac": raw_headers.get("access-control-allow-credentials"),
                "status_code": resp.status,
                "headers": raw_headers,
                "body": body[:51200],
            }
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return {"acao": None, "acac": None, "status_code": 0, "headers": {}, "body": ""}


def extract_domain_info(url: str) -> dict:
    """Extract domain components using tldextract."""
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    registered_domain = ext.registered_domain  # e.g., "example.com"
    fqdn = ext.fqdn or registered_domain       # e.g., "api.example.com"
    scheme = parsed.scheme or "https"
    return {
        "registered_domain": registered_domain,
        "fqdn": fqdn,
        "domain": ext.domain,           # e.g., "example"
        "tld": ext.suffix,              # e.g., "com"
        "subdomain": ext.subdomain,     # e.g., "api"
        "scheme": scheme,
    }


# ── Check 1: Reflected Origin ──────────────────────────────────────────

async def check_reflected_origin(session, url, timeout=10, proxy=None, **kwargs):
    return await _send_cors_request(
        session, url, "https://evil.com",
        CheckName.REFLECTED_ORIGIN, timeout=timeout, proxy=proxy,
    )


# ── Check 2: Null Origin ───────────────────────────────────────────────

async def check_null_origin(session, url, timeout=10, proxy=None, **kwargs):
    return await _send_cors_request(
        session, url, "null",
        CheckName.NULL_ORIGIN, timeout=timeout, proxy=proxy,
    )


# ── Check 3: Pre-domain Bypass (suffix matching flaw) ─────────────────

async def check_pre_domain_bypass(session, url, registered_domain="", timeout=10, proxy=None, **kwargs):
    origin = f"https://evil{registered_domain}"
    return await _send_cors_request(
        session, url, origin,
        CheckName.PRE_DOMAIN_BYPASS, timeout=timeout, proxy=proxy,
    )


# ── Check 4: Post-domain Bypass (prefix matching flaw) ────────────────

async def check_post_domain_bypass(session, url, registered_domain="", timeout=10, proxy=None, **kwargs):
    origin = f"https://{registered_domain}.evil.com"
    return await _send_cors_request(
        session, url, origin,
        CheckName.POST_DOMAIN_BYPASS, timeout=timeout, proxy=proxy,
    )


# ── Check 5: Subdomain Wildcard ───────────────────────────────────────

async def check_subdomain_wildcard(session, url, registered_domain="", timeout=10, proxy=None, **kwargs):
    origin = f"https://evil.{registered_domain}"
    return await _send_cors_request(
        session, url, origin,
        CheckName.SUBDOMAIN_WILDCARD, timeout=timeout, proxy=proxy,
    )


# ── Check 6: Unescaped Dot ────────────────────────────────────────────

async def check_unescaped_dot(session, url, domain="", tld="", timeout=10, proxy=None, **kwargs):
    if not domain or not tld:
        return CORSCheckResult(
            check_name=CheckName.UNESCAPED_DOT, url=url,
            origin_sent="", is_reflected=False,
        )
    # Replace the dot: target.com -> targetXcom
    mangled = f"{domain}X{tld}"
    origin = f"https://{mangled}.evil.com"
    return await _send_cors_request(
        session, url, origin,
        CheckName.UNESCAPED_DOT, timeout=timeout, proxy=proxy,
    )


# ── Check 7: Special Characters Bypass ────────────────────────────────

async def check_special_characters(session, url, registered_domain="", timeout=10, proxy=None, **kwargs):
    special_chars = ["`", "_", "%60", "!", "~", "&", "'", '"', "^", "{", "}", "|"]
    for char in special_chars:
        origin = f"https://{registered_domain}{char}.evil.com"
        result = await _send_cors_request(
            session, url, origin,
            CheckName.SPECIAL_CHARS, timeout=timeout, proxy=proxy,
        )
        if result.is_reflected:
            return result
    # Return last result (not reflected)
    return result


# ── Check 8: HTTP Origin Trust ────────────────────────────────────────

async def check_http_origin_trust(session, url, registered_domain="", scheme="https", timeout=10, proxy=None, **kwargs):
    if scheme != "https":
        return CORSCheckResult(
            check_name=CheckName.HTTP_ORIGIN_TRUST, url=url,
            origin_sent="", is_reflected=False,
        )
    origin = f"http://{registered_domain}"
    return await _send_cors_request(
        session, url, origin,
        CheckName.HTTP_ORIGIN_TRUST, timeout=timeout, proxy=proxy,
    )


# ── Check 9: Third-party Origins ─────────────────────────────────────

THIRD_PARTY_ORIGINS = [
    "https://evil.github.io",
    "https://evil.codepen.io",
    "https://evil.jsfiddle.net",
    "https://evil.jsbin.com",
    "https://evil.repl.it",
    "https://evil.surge.sh",
    "https://evil.netlify.app",
    "https://evil.herokuapp.com",
    "https://evil.pages.dev",
    "https://evil.vercel.app",
]


async def check_third_party_origins(session, url, timeout=10, proxy=None, **kwargs):
    for tp_origin in THIRD_PARTY_ORIGINS:
        result = await _send_cors_request(
            session, url, tp_origin,
            CheckName.THIRD_PARTY_ORIGINS, timeout=timeout, proxy=proxy,
        )
        if result.is_reflected:
            return result
    return result


# ── Check 10: Wildcard ────────────────────────────────────────────────

async def check_wildcard(session, url, timeout=10, proxy=None, **kwargs):
    result = await _send_cors_request(
        session, url, "https://wildcard-test.com",
        CheckName.WILDCARD, timeout=timeout, proxy=proxy,
    )
    # Override: check specifically if ACAO is literally "*"
    if result.acao_received and result.acao_received.strip() == "*":
        result.is_reflected = True
    elif result.acao_received and result.acao_received.strip() != "*":
        # If it reflected our specific origin, that's check 1 (reflected origin), not wildcard
        result.is_reflected = False
    return result


# ── Check 11: Substring Match ────────────────────────────────────────

async def check_substring_match(session, url, domain="", tld="", timeout=10, proxy=None, **kwargs):
    if not domain or len(domain) < 2:
        return CORSCheckResult(
            check_name=CheckName.SUBSTRING_MATCH, url=url,
            origin_sent="", is_reflected=False,
        )
    # Truncate domain: "example" -> "exampl"
    truncated = domain[:-1]
    origin = f"https://{truncated}.{tld}"
    return await _send_cors_request(
        session, url, origin,
        CheckName.SUBSTRING_MATCH, timeout=timeout, proxy=proxy,
    )


# ── Check 12: Include Match ──────────────────────────────────────────

async def check_include_match(session, url, registered_domain="", timeout=10, proxy=None, **kwargs):
    origin = f"https://evil-{registered_domain}.attacker.com"
    return await _send_cors_request(
        session, url, origin,
        CheckName.INCLUDE_MATCH, timeout=timeout, proxy=proxy,
    )


# ── Multi-origin Verification ────────────────────────────────────────

async def verify_dynamic_reflection(session, url, timeout=10, proxy=None):
    """Send a second different origin to confirm dynamic reflection vs static whitelist."""
    return await _send_cors_request(
        session, url, "https://confirm-reflection-test-98765.com",
        CheckName.REFLECTED_ORIGIN, timeout=timeout, proxy=proxy,
    )


# ── All checks registry ──────────────────────────────────────────────

ALL_CHECKS = [
    check_reflected_origin,
    check_null_origin,
    check_pre_domain_bypass,
    check_post_domain_bypass,
    check_subdomain_wildcard,
    check_unescaped_dot,
    check_special_characters,
    check_http_origin_trust,
    check_third_party_origins,
    check_wildcard,
    check_substring_match,
    check_include_match,
]


# ── Preflight OPTIONS Check ──────────────────────────────────────────

async def check_preflight(session, url, timeout=10, proxy=None, **kwargs):
    """Send OPTIONS preflight request and check what methods/headers are allowed."""
    headers = {
        "Origin": "https://evil.com",
        "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "Authorization, Content-Type",
        "User-Agent": DEFAULT_USER_AGENT,
    }
    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.options(
            url, headers=headers, timeout=client_timeout,
            proxy=proxy, allow_redirects=True,
        ) as resp:
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            acao = raw_headers.get("access-control-allow-origin", "")
            acac = raw_headers.get("access-control-allow-credentials", "")
            allow_methods = raw_headers.get("access-control-allow-methods", "")
            allow_headers = raw_headers.get("access-control-allow-headers", "")

            # check if evil origin is allowed in preflight
            is_reflected = acao.strip().lower() in ("https://evil.com", "*")

            return {
                "is_reflected": is_reflected,
                "acao": acao,
                "acac": acac,
                "allow_methods": allow_methods,
                "allow_headers": allow_headers,
                "status_code": resp.status,
                "raw_headers": raw_headers,
            }
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return {
            "is_reflected": False, "acao": "", "acac": "",
            "allow_methods": "", "allow_headers": "",
            "status_code": 0, "raw_headers": {},
        }


# ── Method-specific CORS Testing ─────────────────────────────────────

EXTRA_METHODS = ["POST", "PUT", "DELETE", "PATCH"]


async def check_method_cors(session, url, method, timeout=10, proxy=None, **kwargs):
    """Test CORS reflection on a specific HTTP method."""
    return await _send_cors_request(
        session, url, "https://evil.com",
        CheckName.REFLECTED_ORIGIN, timeout=timeout, proxy=proxy,
        method=method,
    )
