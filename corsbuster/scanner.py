"""Core async scanning engine."""

import asyncio
import random
import ssl
import time

import aiohttp

from . import (
    AnalysisResult, CheckName, DEFAULT_USER_AGENT,
    ScanConfig, ScanReport, Severity,
)
from . import checks as cors_checks
from .analyzer import analyze_finding
from .checkpoint import save_checkpoint


class CORSScanner:
    """Main scanner engine — orchestrates checks, analysis, and findings."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.threads)
        self.findings: list = []
        self.checks_performed = 0
        self._lock = asyncio.Lock()
        self._backoff_hosts: dict = {}
        self._scanned_urls: list = []  # for checkpoint

    def _create_ssl_context(self):
        if not self.config.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

    async def _create_session(self) -> aiohttp.ClientSession:
        ssl_ctx = self._create_ssl_context()
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=self.config.threads * 2)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookie_jar=aiohttp.DummyCookieJar(),
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )

    async def _smart_delay(self):
        """Apply delay between requests. In stealth mode, randomize the delay."""
        if self.config.stealth:
            jitter = random.uniform(0.5, 3.0)
            await asyncio.sleep(jitter)
        elif self.config.delay > 0:
            await asyncio.sleep(self.config.delay)

    async def _check_backoff(self, url: str):
        """If a host returned 429, wait before hitting it again."""
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        backoff = self._backoff_hosts.get(host, 0)
        if backoff > 0:
            await asyncio.sleep(backoff)

    async def _handle_rate_limit(self, url: str, status_code: int):
        """Track 429 responses and increase backoff for that host."""
        if status_code == 429:
            from urllib.parse import urlparse
            host = urlparse(url).netloc
            current = self._backoff_hosts.get(host, 2)
            # Exponential backoff: 2s -> 4s -> 8s -> 16s (max)
            self._backoff_hosts[host] = min(current * 2, 16)

    async def _scan_single_url(
        self,
        session: aiohttp.ClientSession,
        target,
    ) -> list:
        """Scan one URL through the full 3-stage pipeline."""
        async with self.semaphore:
            url = target.url
            extra_headers = target.custom_headers

            # Check backoff before baseline
            await self._check_backoff(url)

            # Get baseline (no Origin)
            baseline = await cors_checks.get_baseline(
                session, url,
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                extra_headers=extra_headers,
            )

            if baseline["status_code"] == 0:
                return []  # Target unreachable

            # Handle rate limiting on baseline
            await self._handle_rate_limit(url, baseline["status_code"])
            if baseline["status_code"] == 429:
                return []  # Being rate-limited, skip

            # Extract domain info
            domain_info = cors_checks.extract_domain_info(url)

            results = []

            for check_fn in cors_checks.ALL_CHECKS:
                try:
                    # Check backoff before each request
                    await self._check_backoff(url)

                    result = await check_fn(
                        session, url,
                        timeout=self.config.timeout,
                        proxy=self.config.proxy,
                        **domain_info,
                    )

                    async with self._lock:
                        self.checks_performed += 1

                    # Handle rate limiting
                    await self._handle_rate_limit(url, result.status_code)
                    if result.status_code == 429:
                        # Back off and retry once
                        await self._check_backoff(url)
                        result = await check_fn(
                            session, url,
                            timeout=self.config.timeout,
                            proxy=self.config.proxy,
                            **domain_info,
                        )

                    # Multi-origin verification for reflected origin
                    if (
                        result.is_reflected
                        and result.check_name == CheckName.REFLECTED_ORIGIN
                        and result.acao_received
                        and result.acao_received.strip() != "*"
                    ):
                        await self._smart_delay()
                        verify = await cors_checks.verify_dynamic_reflection(
                            session, url,
                            timeout=self.config.timeout,
                            proxy=self.config.proxy,
                        )
                        if not verify.is_reflected:
                            result.is_reflected = False

                    # Analyze if reflected or verbose mode
                    if result.is_reflected or self.config.verbose:
                        analysis = analyze_finding(
                            check_result=result,
                            baseline=baseline,
                            request_headers=extra_headers,
                        )
                        results.append(analysis)

                    # Smart delay between checks
                    await self._smart_delay()

                except Exception:
                    pass

            # Method-specific testing (only if --methods and GET showed reflection)
            has_get_reflection = any(
                r.check_result.is_reflected for r in results
                if r.check_result.check_name == CheckName.REFLECTED_ORIGIN
            )
            if self.config.methods and has_get_reflection:
                for method in cors_checks.EXTRA_METHODS:
                    try:
                        await self._check_backoff(url)
                        result = await cors_checks.check_method_cors(
                            session, url, method,
                            timeout=self.config.timeout,
                            proxy=self.config.proxy,
                        )
                        async with self._lock:
                            self.checks_performed += 1
                        if result.is_reflected or self.config.verbose:
                            analysis = analyze_finding(result, baseline, extra_headers)
                            analysis.explanation = f"[{method}] {analysis.explanation}"
                            results.append(analysis)
                        await self._smart_delay()
                    except Exception:
                        pass

            # Preflight OPTIONS check
            if self.config.methods:
                try:
                    preflight = await cors_checks.check_preflight(
                        session, url,
                        timeout=self.config.timeout,
                        proxy=self.config.proxy,
                    )
                    async with self._lock:
                        self.checks_performed += 1
                    if preflight["is_reflected"] and preflight["allow_methods"]:
                        dangerous = {"PUT", "DELETE", "PATCH"}
                        allowed = {m.strip().upper() for m in preflight["allow_methods"].split(",")}
                        if dangerous & allowed:
                            from . import CORSCheckResult as CR
                            pfr = CR(
                                check_name=CheckName.REFLECTED_ORIGIN,
                                url=url,
                                origin_sent="https://evil.com [OPTIONS preflight]",
                                acao_received=preflight["acao"],
                                acac_received=preflight["acac"],
                                is_reflected=True,
                                raw_headers=preflight["raw_headers"],
                                status_code=preflight["status_code"],
                            )
                            analysis = analyze_finding(pfr, baseline, extra_headers)
                            methods_str = ", ".join(sorted(dangerous & allowed))
                            analysis.explanation = (
                                f"PREFLIGHT: Dangerous methods ({methods_str}) allowed "
                                f"cross-origin via OPTIONS preflight. {analysis.explanation}"
                            )
                            results.append(analysis)
                except Exception:
                    pass

            # save checkpoint
            async with self._lock:
                self._scanned_urls.append(url)
            if self.config.resume:
                save_checkpoint(self._scanned_urls, self.config)

            return results

    async def scan(self) -> ScanReport:
        """Scan all targets and produce a ScanReport."""
        start_time = time.time()

        async with await self._create_session() as session:
            tasks = [
                self._scan_single_url(session, target)
                for target in self.config.targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten results
        for result in results:
            if isinstance(result, list):
                self.findings.extend(result)

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return ScanReport(
            targets_scanned=len(self.config.targets),
            checks_performed=self.checks_performed,
            findings=self.findings,
            duration_seconds=round(time.time() - start_time, 2),
        )
