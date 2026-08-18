import asyncio
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db_api_key
from app.models.schemas import (
    EmailHeaderDetails,
    IOCType,
    SourceResult,
    SubScanItem,
    Verdict,
)
from app.services.analyzers.abuseipdb import AbuseIPDBAnalyzer
from app.services.analyzers.base import BaseAnalyzer
from app.services.analyzers.email_parser import EmailHeaderAnalyzer
from app.services.analyzers.malwarebazaar import MalwareBazaarAnalyzer
from app.services.analyzers.safebrowsing import SafeBrowsingAnalyzer
from app.services.analyzers.urlscan import URLScanAnalyzer
from app.services.analyzers.virustotal import VirusTotalAnalyzer
from app.services.analyzers.whois_rdap import WhoisRdapAnalyzer
from app.services.classifier import classify_ioc

async def get_active_api_keys(session: Optional[AsyncSession] = None) -> Dict[str, Optional[str]]:
    """Retrieve API keys from database override or settings."""
    keys = {
        "virustotal": settings.VIRUSTOTAL_API_KEY,
        "abuseipdb": settings.ABUSEIPDB_API_KEY,
        "urlscan": settings.URLSCAN_API_KEY,
        "safebrowsing": settings.SAFEBROWSING_API_KEY,
        "malwarebazaar": settings.MALWAREBAZAAR_API_KEY,
        "shodan": settings.SHODAN_API_KEY,
        "greynoise": settings.GREYNOISE_API_KEY,
    }
    
    if session:
        for key_name in keys.keys():
            db_val = await get_db_api_key(session, key_name)
            if db_val:
                keys[key_name] = db_val
                
    return keys

def get_analyzers_for_type(ioc_type: IOCType, keys: Dict[str, Optional[str]]) -> List[BaseAnalyzer]:
    """Instantiate and filter all analyzers that support the target IOC type."""
    all_analyzers = [
        VirusTotalAnalyzer(api_key=keys.get("virustotal")),
        AbuseIPDBAnalyzer(api_key=keys.get("abuseipdb")),
        URLScanAnalyzer(api_key=keys.get("urlscan")),
        SafeBrowsingAnalyzer(api_key=keys.get("safebrowsing")),
        MalwareBazaarAnalyzer(api_key=keys.get("malwarebazaar")),
        WhoisRdapAnalyzer(),
        EmailHeaderAnalyzer(),
    ]
    return [a for a in all_analyzers if a.supports(ioc_type)]

async def dispatch_analysis(
    indicator: str,
    ioc_type: IOCType,
    session: Optional[AsyncSession] = None,
    cascade_depth: int = 1,
) -> tuple[List[SourceResult], Optional[EmailHeaderDetails]]:
    """
    Executes parallel analysis across all compatible threat intelligence providers.
    If the indicator is an email or raw header, cascades scans into extracted URLs and attachment hashes.
    """
    keys = await get_active_api_keys(session)
    analyzers = get_analyzers_for_type(ioc_type, keys)

    if not analyzers:
        return [], None

    # Execute all primary analyzers in parallel with graceful exception trapping
    tasks = [analyzer.analyze(indicator, ioc_type) for analyzer in analyzers]
    results: List[SourceResult] = await asyncio.gather(*tasks, return_exceptions=False)

    email_details: Optional[EmailHeaderDetails] = None

    # If IOC is an email header or email with embedded indicators, cascade scans
    if ioc_type in [IOCType.EMAIL, IOCType.EMAIL_HEADER]:
        email_analyzer = EmailHeaderAnalyzer()
        email_details = email_analyzer.parse_email_text(indicator)

        if cascade_depth > 0:
            sub_scans: List[SubScanItem] = []
            
            # Cascade embedded URLs (cap at 5 to avoid quota exhaustion)
            for url in email_details.extracted_urls[:5]:
                url_clf = classify_ioc(url)
                sub_results, _ = await dispatch_analysis(url_clf.normalized, url_clf.ioc_type, session, cascade_depth=0)
                # Compute highest severity for sub-item
                top_verdict = Verdict.CLEAN
                top_score = 0.0
                summary = "Clean link"
                for r in sub_results:
                    if r.verdict == Verdict.MALICIOUS:
                        top_verdict = Verdict.MALICIOUS
                        top_score = max(top_score, r.confidence_score)
                        summary = r.summary
                        break
                    elif r.verdict == Verdict.SUSPICIOUS:
                        top_verdict = Verdict.SUSPICIOUS
                        top_score = max(top_score, r.confidence_score)
                        summary = r.summary

                sub_scans.append(SubScanItem(
                    indicator=url,
                    ioc_type=url_clf.ioc_type,
                    verdict=top_verdict,
                    confidence_score=top_score,
                    summary=summary,
                ))

            # Cascade attachment hashes (cap at 5)
            for file_hash in email_details.extracted_hashes[:5]:
                hash_clf = classify_ioc(file_hash)
                sub_results, _ = await dispatch_analysis(hash_clf.normalized, hash_clf.ioc_type, session, cascade_depth=0)
                top_verdict = Verdict.CLEAN
                top_score = 0.0
                summary = "Clean attachment hash"
                for r in sub_results:
                    if r.verdict == Verdict.MALICIOUS:
                        top_verdict = Verdict.MALICIOUS
                        top_score = max(top_score, r.confidence_score)
                        summary = r.summary
                        break
                    elif r.verdict == Verdict.SUSPICIOUS:
                        top_verdict = Verdict.SUSPICIOUS
                        top_score = max(top_score, r.confidence_score)
                        summary = r.summary

                sub_scans.append(SubScanItem(
                    indicator=file_hash,
                    ioc_type=hash_clf.ioc_type,
                    verdict=top_verdict,
                    confidence_score=top_score,
                    summary=summary,
                ))

            email_details.sub_scans = sub_scans

    return results, email_details
