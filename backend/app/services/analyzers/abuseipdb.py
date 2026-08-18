import hashlib
from typing import Any, Dict
import httpx

from app.models.schemas import IOCType, SourceResult, Verdict
from app.services.analyzers.base import BaseAnalyzer
from app.config import settings

class AbuseIPDBAnalyzer(BaseAnalyzer):
    name: str = "AbuseIPDB"
    supported_types = [IOCType.IPV4, IOCType.IPV6]
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    async def _scan_real(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": indicator,
            "maxAgeInDays": 90,
            "verbose": ""
        }

        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(self.BASE_URL, headers=headers, params=params)
            
            if response.status_code == 429:
                raise Exception("AbuseIPDB daily query limit reached (HTTP 429).")
                
            response.raise_for_status()
            data = response.json().get("data", {})
            
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country_code = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown ISP")
            usage_type = data.get("usageType", "Unknown")
            is_whitelisted = data.get("isWhitelisted", False)

            if is_whitelisted or abuse_score == 0:
                verdict = Verdict.CLEAN
                score = 0.0
            elif abuse_score >= 60 or total_reports >= 25:
                verdict = Verdict.MALICIOUS
                score = float(abuse_score)
            elif abuse_score >= 20 or total_reports >= 5:
                verdict = Verdict.SUSPICIOUS
                score = float(abuse_score)
            else:
                verdict = Verdict.CLEAN
                score = float(abuse_score)

            summary = f"Abuse confidence: {abuse_score}% ({total_reports} reports). ISP: {isp} ({country_code})"
            detail_url = f"https://www.abuseipdb.com/check/{indicator}"

            return SourceResult(
                name=self.name,
                ioc_type=ioc_type,
                verdict=verdict,
                confidence_score=score,
                detail_url=detail_url,
                summary=summary,
                raw_data={
                    "abuseConfidenceScore": abuse_score,
                    "totalReports": total_reports,
                    "countryCode": country_code,
                    "isp": isp,
                    "usageType": usage_type,
                    "isWhitelisted": is_whitelisted,
                    "lastReportedAt": data.get("lastReportedAt"),
                },
                status="ok",
            )

    def _mock_response(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        detail_url = f"https://www.abuseipdb.com/check/{indicator}"
        
        # Test known IPs
        if indicator in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]:
            abuse_score = 0
            total_reports = 0
            country_code = "US"
            isp = "Google LLC / Cloudflare"
            verdict = Verdict.CLEAN
        elif any(bad in indicator for bad in ["185.", "45.", "194.", "91."]):
            abuse_score = 88
            total_reports = 142
            country_code = "RU"
            isp = "Hosting Solutions LTD (Bulletproof)"
            verdict = Verdict.MALICIOUS
        else:
            h_val = int(hashlib.md5(indicator.encode()).hexdigest()[:4], 16) % 100
            if h_val > 75:
                abuse_score = 75
                total_reports = 68
                country_code = "NL"
                isp = "DataCamp S.R.O."
                verdict = Verdict.MALICIOUS
            elif h_val > 45:
                abuse_score = 35
                total_reports = 8
                country_code = "DE"
                isp = "Hetzner Online GmbH"
                verdict = Verdict.SUSPICIOUS
            else:
                abuse_score = 0
                total_reports = 0
                country_code = "US"
                isp = "Amazon Technologies Inc."
                verdict = Verdict.CLEAN

        summary = f"Abuse confidence: {abuse_score}% ({total_reports} reports). ISP: {isp} ({country_code}) [Mock]"

        return SourceResult(
            name=self.name,
            ioc_type=ioc_type,
            verdict=verdict,
            confidence_score=float(abuse_score),
            detail_url=detail_url,
            summary=summary,
            raw_data={
                "abuseConfidenceScore": abuse_score,
                "totalReports": total_reports,
                "countryCode": country_code,
                "isp": isp,
                "mock_simulated": True,
            },
            status="mocked",
        )
