import hashlib
from typing import Any, Dict
import httpx

from app.models.schemas import IOCType, SourceResult, Verdict
from app.services.analyzers.base import BaseAnalyzer
from app.config import settings

class SafeBrowsingAnalyzer(BaseAnalyzer):
    name: str = "Google Safe Browsing"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def _scan_real(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        url_to_check = indicator if indicator.startswith("http") else f"http://{indicator}"
        params = {"key": self.api_key}
        
        payload = {
            "client": {
                "clientId": "threatscope-scanner",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url_to_check}
                ]
            }
        }

        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(self.BASE_URL, params=params, json=payload)
            
            if response.status_code == 429:
                raise Exception("Google Safe Browsing API rate limit exceeded.")
                
            response.raise_for_status()
            data = response.json()
            matches = data.get("matches", [])

            if matches:
                threat_types = [m.get("threatType") for m in matches]
                threat_str = ", ".join(threat_types)
                return SourceResult(
                    name=self.name,
                    ioc_type=ioc_type,
                    verdict=Verdict.MALICIOUS,
                    confidence_score=95.0,
                    detail_url="https://transparencyreport.google.com/safe-browsing/search",
                    summary=f"Flagged as hazardous by Google Safe Browsing: {threat_str}",
                    raw_data={"matches": matches},
                    status="ok",
                )
            else:
                return SourceResult(
                    name=self.name,
                    ioc_type=ioc_type,
                    verdict=Verdict.CLEAN,
                    confidence_score=5.0,
                    detail_url="https://transparencyreport.google.com/safe-browsing/search",
                    summary="No unsafe threats detected by Google Safe Browsing",
                    raw_data={"matches": []},
                    status="ok",
                )

    def _mock_response(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        detail_url = "https://transparencyreport.google.com/safe-browsing/search"
        ind_lower = indicator.lower()
        
        if any(bad in ind_lower for bad in ["malware", "phish", "deceptive", "payload", "trojan", "exploit"]):
            verdict = Verdict.MALICIOUS
            score = 90.0
            summary = "Flagged by Safe Browsing: SOCIAL_ENGINEERING / MALWARE [Mock]"
            matches = [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"}]
        elif any(clean in ind_lower for clean in ["google.com", "microsoft.com", "github.com", "apple.com"]):
            verdict = Verdict.CLEAN
            score = 0.0
            summary = "Clean / Benign site status [Mock]"
            matches = []
        else:
            h_val = int(hashlib.md5(indicator.encode()).hexdigest()[:4], 16) % 100
            if h_val > 80:
                verdict = Verdict.MALICIOUS
                score = 85.0
                summary = "Flagged by Safe Browsing: UNWANTED_SOFTWARE [Mock]"
                matches = [{"threatType": "UNWANTED_SOFTWARE"}]
            else:
                verdict = Verdict.CLEAN
                score = 0.0
                summary = "No unsafe content flagged by Safe Browsing [Mock]"
                matches = []

        return SourceResult(
            name=self.name,
            ioc_type=ioc_type,
            verdict=verdict,
            confidence_score=score,
            detail_url=detail_url,
            summary=summary,
            raw_data={"matches": matches, "mock_simulated": True},
            status="mocked",
        )
