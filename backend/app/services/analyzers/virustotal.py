import base64
import hashlib
from typing import Any, Dict
import httpx

from app.models.schemas import IOCType, SourceResult, Verdict
from app.services.analyzers.base import BaseAnalyzer
from app.config import settings

class VirusTotalAnalyzer(BaseAnalyzer):
    name: str = "VirusTotal"
    supported_types = [
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.URL,
        IOCType.DOMAIN,
        IOCType.IPV4,
        IOCType.IPV6,
    ]

    BASE_URL = "https://www.virustotal.com/api/v3"

    def _get_url_id(self, url: str) -> str:
        """Encode URL into VT URL identifier (URL-safe base64 without padding)."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def _scan_real(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            endpoint = ""
            detail_url = ""

            if ioc_type in [IOCType.MD5, IOCType.SHA1, IOCType.SHA256]:
                endpoint = f"{self.BASE_URL}/files/{indicator}"
                detail_url = f"https://www.virustotal.com/gui/file/{indicator}"
            elif ioc_type == IOCType.URL:
                url_id = self._get_url_id(indicator)
                endpoint = f"{self.BASE_URL}/urls/{url_id}"
                detail_url = f"https://www.virustotal.com/gui/url/{url_id}"
            elif ioc_type == IOCType.DOMAIN:
                endpoint = f"{self.BASE_URL}/domains/{indicator}"
                detail_url = f"https://www.virustotal.com/gui/domain/{indicator}"
            elif ioc_type in [IOCType.IPV4, IOCType.IPV6]:
                endpoint = f"{self.BASE_URL}/ip_addresses/{indicator}"
                detail_url = f"https://www.virustotal.com/gui/ip-address/{indicator}"

            response = await client.get(endpoint, headers=headers)

            if response.status_code == 404:
                return SourceResult(
                    name=self.name,
                    ioc_type=ioc_type,
                    verdict=Verdict.UNKNOWN,
                    confidence_score=10.0,
                    detail_url=detail_url,
                    summary="Indicator not found in VirusTotal dataset (0 detections).",
                    raw_data={"status_code": 404, "not_found": True},
                    status="ok",
                )

            if response.status_code == 429:
                raise Exception("VirusTotal API rate limit exceeded (HTTP 429).")

            response.raise_for_status()
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total_engines = malicious + suspicious + harmless + undetected

            # Scoring calculation
            if total_engines == 0:
                verdict = Verdict.UNKNOWN
                score = 0.0
            elif malicious >= 3:
                verdict = Verdict.MALICIOUS
                score = min(100.0, 50.0 + (malicious / max(1, total_engines)) * 50.0 + (malicious * 3))
            elif malicious in [1, 2] or suspicious >= 2:
                verdict = Verdict.SUSPICIOUS
                score = 40.0 + (malicious * 10) + (suspicious * 5)
            elif harmless > 5 and malicious == 0:
                verdict = Verdict.CLEAN
                score = 5.0
            else:
                verdict = Verdict.CLEAN if harmless > 0 else Verdict.UNKNOWN
                score = 10.0

            summary = f"Flagged by {malicious}/{total_engines} security vendors"
            if suspicious > 0:
                summary += f" ({suspicious} suspicious)"

            return SourceResult(
                name=self.name,
                ioc_type=ioc_type,
                verdict=verdict,
                confidence_score=round(score, 1),
                detail_url=detail_url,
                summary=summary,
                raw_data={
                    "last_analysis_stats": stats,
                    "reputation": attributes.get("reputation", 0),
                    "tags": attributes.get("tags", []),
                    "popular_threat_classification": attributes.get("popular_threat_classification", {}),
                },
                status="ok",
            )

    def _mock_response(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        """Realistic mock response based on deterministic hashing of the indicator."""
        detail_url = f"https://www.virustotal.com/gui/search/{indicator}"
        
        # Test indicators check
        ind_lower = indicator.lower()
        
        # Known malware signatures or keywords for testing
        is_known_bad = any(bad in ind_lower for bad in ["malware", "evil", "phish", "trojan", "wannacry", "bad", "c2", "ransom"])
        is_known_clean = any(clean in ind_lower for clean in ["google", "microsoft", "cloudflare", "8.8.8.8", "1.1.1.1", "github.com", "apple.com"])
        
        if is_known_bad:
            malicious = 47
            suspicious = 3
            harmless = 2
            undetected = 20
            verdict = Verdict.MALICIOUS
            score = 92.0
            threat_name = "Trojan.Generic / Ransomware"
        elif is_known_clean:
            malicious = 0
            suspicious = 0
            harmless = 68
            undetected = 4
            verdict = Verdict.CLEAN
            score = 0.0
            threat_name = None
        else:
            # Deterministic hash mock for generic inputs
            h_val = int(hashlib.md5(indicator.encode()).hexdigest()[:6], 16) % 100
            if h_val > 80:
                malicious = 24
                suspicious = 2
                harmless = 5
                undetected = 41
                verdict = Verdict.MALICIOUS
                score = 78.0
                threat_name = "Win32.Suspicious.Agent"
            elif h_val > 55:
                malicious = 2
                suspicious = 4
                harmless = 30
                undetected = 36
                verdict = Verdict.SUSPICIOUS
                score = 45.0
                threat_name = "Heuristic.Suspicious"
            else:
                malicious = 0
                suspicious = 0
                harmless = 62
                undetected = 10
                verdict = Verdict.CLEAN
                score = 5.0
                threat_name = None

        total = malicious + suspicious + harmless + undetected
        summary = f"Flagged by {malicious}/{total} security engines (Mock Simulation)"
        
        return SourceResult(
            name=self.name,
            ioc_type=ioc_type,
            verdict=verdict,
            confidence_score=score,
            detail_url=detail_url,
            summary=summary,
            raw_data={
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected
                },
                "mock_simulated": True,
                "threat_name": threat_name,
                "reputation": -50 if malicious > 5 else (50 if harmless > 30 else 0)
            },
            status="mocked",
        )
