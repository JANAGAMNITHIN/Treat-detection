from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, Optional
import httpx

from app.models.schemas import IOCType, SourceResult, Verdict
from app.services.analyzers.base import BaseAnalyzer
from app.config import settings

class WhoisRdapAnalyzer(BaseAnalyzer):
    name: str = "WHOIS / RDAP"
    supported_types = [IOCType.DOMAIN, IOCType.URL]
    BASE_URL = "https://rdap.org/domain"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key=api_key or "PUBLIC_RDAP")

    def _extract_domain(self, indicator: str, ioc_type: IOCType) -> str:
        if ioc_type == IOCType.URL:
            # strip scheme
            no_scheme = indicator.split("://")[-1]
            return no_scheme.split("/")[0].split(":")[0].lower()
        return indicator.split(":")[0].lower()

    async def _scan_real(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        domain = self._extract_domain(indicator, ioc_type)
        endpoint = f"{self.BASE_URL}/{domain}"
        detail_url = f"https://lookup.icann.org/en/lookup?q={domain}"

        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = await client.get(endpoint)
            
            if response.status_code == 404:
                return SourceResult(
                    name=self.name,
                    ioc_type=ioc_type,
                    verdict=Verdict.SUSPICIOUS,
                    confidence_score=35.0,
                    detail_url=detail_url,
                    summary="Domain not found or unregistered in global RDAP registries (potential NXDOMAIN or DGA).",
                    raw_data={"status_code": 404},
                    status="ok",
                )

            if response.status_code != 200:
                # Return graceful fallback if RDAP server gives error
                return self._mock_response(indicator, ioc_type)

            data = response.json()
            events = data.get("events", [])
            
            registration_date_str = None
            expiration_date_str = None
            last_changed_str = None

            for ev in events:
                action = ev.get("eventAction")
                date_val = ev.get("eventDate")
                if action == "registration":
                    registration_date_str = date_val
                elif action == "expiration":
                    expiration_date_str = date_val
                elif action == "last changed":
                    last_changed_str = date_val

            # Calculate domain age
            age_days = None
            is_newly_registered = False
            if registration_date_str:
                try:
                    # Clean ISO format
                    dt_str = registration_date_str.replace("Z", "+00:00")
                    reg_dt = datetime.fromisoformat(dt_str)
                    now_dt = datetime.now(timezone.utc)
                    age_days = (now_dt - reg_dt).days
                    if age_days < 30:
                        is_newly_registered = True
                except Exception:
                    pass

            # Extract registrar
            registrar_name = "Unknown Registrar"
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and item[0] == "fn":
                                registrar_name = item[3]
                                break

            # Score logic based on domain age
            if age_days is not None:
                if age_days < 7:
                    verdict = Verdict.MALICIOUS
                    score = 75.0
                    summary = f"Newly registered domain ({age_days} days old). Registrar: {registrar_name}. High threat risk."
                elif age_days < 30:
                    verdict = Verdict.SUSPICIOUS
                    score = 45.0
                    summary = f"Young domain ({age_days} days old). Registrar: {registrar_name}. Elevated monitoring recommended."
                elif age_days < 90:
                    verdict = Verdict.SUSPICIOUS
                    score = 25.0
                    summary = f"Recent domain ({age_days} days old). Registrar: {registrar_name}."
                else:
                    verdict = Verdict.CLEAN
                    score = 0.0
                    summary = f"Established domain ({age_days} days old / {round(age_days/365, 1)} years). Registrar: {registrar_name}."
            else:
                verdict = Verdict.UNKNOWN
                score = 0.0
                summary = f"Registrar: {registrar_name}. Registration timestamp unavailable."

            return SourceResult(
                name=self.name,
                ioc_type=ioc_type,
                verdict=verdict,
                confidence_score=score,
                detail_url=detail_url,
                summary=summary,
                raw_data={
                    "domain": domain,
                    "registrar": registrar_name,
                    "age_days": age_days,
                    "registration_date": registration_date_str,
                    "expiration_date": expiration_date_str,
                    "status": data.get("status", []),
                },
                status="ok",
            )

    def _mock_response(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        domain = self._extract_domain(indicator, ioc_type)
        detail_url = f"https://lookup.icann.org/en/lookup?q={domain}"

        if any(bad in domain for bad in ["phish", "malware", "update-bank", "xyz", "top", "free-gift"]):
            age_days = 4
            registrar = "NameCheap, Inc. / Privacy Protected"
            verdict = Verdict.SUSPICIOUS
            score = 65.0
            summary = f"Newly registered domain ({age_days} days old). Registrar: {registrar}. [Mock Heuristics]"
        elif any(clean in domain for clean in ["google.com", "microsoft.com", "github.com", "apple.com", "cloudflare.com"]):
            age_days = 8420
            registrar = "MarkMonitor Inc."
            verdict = Verdict.CLEAN
            score = 0.0
            summary = f"Established enterprise domain ({round(age_days/365, 1)} years old). Registrar: {registrar}. [Mock]"
        else:
            h_val = int(hashlib.md5(domain.encode()).hexdigest()[:4], 16) % 100
            if h_val > 70:
                age_days = 12
                registrar = "Tucows Domains Inc."
                verdict = Verdict.SUSPICIOUS
                score = 45.0
                summary = f"Young domain ({age_days} days old). Registrar: {registrar}. [Mock]"
            else:
                age_days = 1250
                registrar = "GoDaddy.com, LLC"
                verdict = Verdict.CLEAN
                score = 0.0
                summary = f"Established domain ({round(age_days/365, 1)} years old). Registrar: {registrar}. [Mock]"

        return SourceResult(
            name=self.name,
            ioc_type=ioc_type,
            verdict=verdict,
            confidence_score=score,
            detail_url=detail_url,
            summary=summary,
            raw_data={
                "domain": domain,
                "registrar": registrar,
                "age_days": age_days,
                "mock_simulated": True,
            },
            status="mocked",
        )
