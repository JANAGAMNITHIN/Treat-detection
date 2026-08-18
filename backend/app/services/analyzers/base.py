import abc
import time
from typing import Any, Dict, Optional
from app.models.schemas import IOCType, SourceResult, Verdict

class BaseAnalyzer(abc.ABC):
    name: str = "BaseAnalyzer"
    supported_types: list[IOCType] = []

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    @abc.abstractmethod
    async def _scan_real(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        """Execute the real threat intelligence API request."""
        pass

    @abc.abstractmethod
    def _mock_response(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        """Generate realistic mock response when no API key is provided."""
        pass

    async def analyze(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        """
        Executes analysis with timing, error handling, rate-limit resilience,
        and fallback to mock intelligence if keys are not present.
        """
        if not self.supports(ioc_type):
            return SourceResult(
                name=self.name,
                ioc_type=ioc_type,
                verdict=Verdict.UNKNOWN,
                confidence_score=0.0,
                summary=f"{self.name} does not support IOC type {ioc_type.value}",
                status="skipped",
            )

        start_time = time.perf_counter()
        
        # If no API key configured, use realistic mock engine
        if not self.api_key:
            res = self._mock_response(indicator, ioc_type)
            res.duration_ms = round((time.perf_counter() - start_time) * 1000, 1)
            res.status = "mocked"
            return res

        try:
            res = await self._scan_real(indicator, ioc_type)
            res.duration_ms = round((time.perf_counter() - start_time) * 1000, 1)
            return res
        except Exception as exc:
            duration = round((time.perf_counter() - start_time) * 1000, 1)
            error_str = str(exc)
            
            # Check for rate limits or network issues
            if "429" in error_str or "Too Many Requests" in error_str:
                return SourceResult(
                    name=self.name,
                    ioc_type=ioc_type,
                    verdict=Verdict.UNKNOWN,
                    confidence_score=0.0,
                    summary=f"{self.name} free tier rate limit exceeded (HTTP 429). Falling back to offline heuristics.",
                    status="rate_limited",
                    duration_ms=duration,
                    error_message=error_str,
                )
            elif "401" in error_str or "403" in error_str:
                return SourceResult(
                    name=self.name,
                    ioc_type=ioc_type,
                    verdict=Verdict.UNKNOWN,
                    confidence_score=0.0,
                    summary=f"{self.name} API key invalid or forbidden (HTTP 401/403).",
                    status="error",
                    duration_ms=duration,
                    error_message=error_str,
                )
            else:
                return SourceResult(
                    name=self.name,
                    ioc_type=ioc_type,
                    verdict=Verdict.UNKNOWN,
                    confidence_score=0.0,
                    summary=f"{self.name} query failed: {error_str[:120]}",
                    status="error",
                    duration_ms=duration,
                    error_message=error_str,
                )
