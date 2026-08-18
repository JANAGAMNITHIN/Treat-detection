import hashlib
from typing import Any, Dict
from urllib.parse import quote, urlparse
import httpx

from app.models.schemas import IOCType, SourceResult, Verdict
from app.services.analyzers.base import BaseAnalyzer
from app.config import settings

class URLScanAnalyzer(BaseAnalyzer):
    name: str = "URLScan.io"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    BASE_URL = "https://urlscan.io/api/v1"

    async def _scan_real(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        headers = {
            "API-Key": self.api_key or "",
            "Accept": "application/json",
        }

        # Query search API for existing historical scans
        query = f"page.domain:{indicator}" if ioc_type == IOCType.DOMAIN else f'page.url:"{indicator}"'
        search_endpoint = f"{self.BASE_URL}/search/?q={quote(query)}&size=3"

        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(search_endpoint, headers=headers)
            
            if response.status_code == 429:
                raise Exception("URLScan API rate limit exceeded.")
                
            response.raise_for_status()
            data = response.json()
            results = data.get("results", [])

            if not results:
                return SourceResult(
                    name=self.name,
                    ioc_type=ioc_type,
                    verdict=Verdict.UNKNOWN,
                    confidence_score=0.0,
                    summary="No recent scans recorded on URLScan.io",
                    detail_url=f"https://urlscan.io/search/#{quote(query)}",
                    raw_data={"total": 0, "results": []},
                    status="ok",
                )

            top_hit = results[0]
            page = top_hit.get("page", {})
            verdicts = top_hit.get("verdicts", {})
            overall_verdict = verdicts.get("overall", {})
            
            is_malicious = overall_verdict.get("malicious", False)
            score = overall_verdict.get("score", 0)
            categories = overall_verdict.get("categories", [])
            screenshot_url = top_hit.get("screenshot", "")
            result_url = top_hit.get("result", "")

            if is_malicious or score >= 50:
                verdict = Verdict.MALICIOUS
                conf_score = max(70.0, float(score))
            elif score >= 20:
                verdict = Verdict.SUSPICIOUS
                conf_score = float(score)
            else:
                verdict = Verdict.CLEAN
                conf_score = float(score)

            cats_str = f" [{', '.join(categories)}]" if categories else ""
            summary = f"Overall score: {score}/100{cats_str}. Primary IP: {page.get('ip', 'N/A')} ({page.get('country', '')})"

            return SourceResult(
                name=self.name,
                ioc_type=ioc_type,
                verdict=verdict,
                confidence_score=conf_score,
                detail_url=result_url or f"https://urlscan.io/search/#{quote(query)}",
                summary=summary,
                raw_data={
                    "page": page,
                    "verdicts": verdicts,
                    "screenshot": screenshot_url,
                    "scan_id": top_hit.get("_id"),
                },
                status="ok",
            )

    def _mock_response(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        query = quote(indicator)
        detail_url = f"https://urlscan.io/search/#{query}"
        
        ind_lower = indicator.lower()
        if any(bad in ind_lower for bad in ["phish", "steal", "login-verify", "bank", "secure-update", "malware"]):
            verdict = Verdict.MALICIOUS
            score = 85.0
            summary = "Flagged as Malicious Phishing target (Brand Impersonation / Credential Harvest) [Mock]"
            cats = ["phishing", "malicious"]
        elif any(clean in ind_lower for clean in ["google.com", "microsoft.com", "github.com", "apple.com", "amazon.com"]):
            verdict = Verdict.CLEAN
            score = 0.0
            summary = "Known benign enterprise domain / service [Mock]"
            cats = []
        else:
            h_val = int(hashlib.md5(indicator.encode()).hexdigest()[:4], 16) % 100
            if h_val > 75:
                verdict = Verdict.SUSPICIOUS
                score = 45.0
                summary = "Unclassified domain with newly registered TLS certificate [Mock]"
                cats = ["suspicious"]
            else:
                verdict = Verdict.CLEAN
                score = 0.0
                summary = "Clean scan record, no malicious behavior observed [Mock]"
                cats = []

        return SourceResult(
            name=self.name,
            ioc_type=ioc_type,
            verdict=verdict,
            confidence_score=score,
            detail_url=detail_url,
            summary=summary,
            raw_data={
                "mock_simulated": True,
                "categories": cats,
                "score": score,
            },
            status="mocked",
        )
