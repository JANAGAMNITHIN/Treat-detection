from datetime import datetime
import uuid
from typing import Dict, List, Optional

from app.models.schemas import (
    EmailHeaderDetails,
    IOCClassification,
    IOCType,
    RiskLevel,
    ScanResponse,
    ScoringFactor,
    SourceResult,
    Verdict,
)

SOURCE_WEIGHTS = {
    "VirusTotal": 1.0,
    "MalwareBazaar (abuse.ch)": 1.0,
    "Google Safe Browsing": 0.9,
    "AbuseIPDB": 0.85,
    "URLScan.io": 0.75,
    "Email Header & MIME Inspector": 0.9,
    "WHOIS / RDAP": 0.6,
}

def aggregate_and_score(
    classification: IOCClassification,
    sources: List[SourceResult],
    email_details: Optional[EmailHeaderDetails] = None,
    scan_id: Optional[str] = None,
    is_cached: bool = False,
    cached_from: Optional[datetime] = None,
) -> ScanResponse:
    """
    Combines results from multiple threat intelligence providers into a normalized,
    weighted risk score (0-100), categorical verdict, and clear scoring explanation breakdown.
    """
    breakdown: List[ScoringFactor] = []
    raw_data: Dict[str, any] = {}

    malicious_votes = 0
    suspicious_votes = 0
    clean_votes = 0
    total_valid_sources = 0

    accumulated_points = 0.0
    max_possible_points = 0.0

    for src in sources:
        if src.status == "skipped":
            continue

        raw_data[src.name] = src.raw_data
        weight = SOURCE_WEIGHTS.get(src.name, 0.7)
        max_possible_points += 100.0 * weight
        total_valid_sources += 1

        points = (src.confidence_score) * weight
        accumulated_points += points

        if src.verdict == Verdict.MALICIOUS:
            malicious_votes += 1
            breakdown.append(ScoringFactor(
                source=src.name,
                weight=weight,
                points_contributed=round(points, 1),
                reason=f"Flagged as Malicious: {src.summary}",
            ))
        elif src.verdict == Verdict.SUSPICIOUS:
            suspicious_votes += 1
            breakdown.append(ScoringFactor(
                source=src.name,
                weight=weight,
                points_contributed=round(points, 1),
                reason=f"Flagged as Suspicious: {src.summary}",
            ))
        elif src.verdict == Verdict.CLEAN:
            clean_votes += 1
            breakdown.append(ScoringFactor(
                source=src.name,
                weight=weight,
                points_contributed=0.0,
                reason=f"Verified Clean: {src.summary}",
            ))
        else:
            breakdown.append(ScoringFactor(
                source=src.name,
                weight=weight,
                points_contributed=0.0,
                reason=f"No threat signals found: {src.summary}",
            ))

    # Cascade inspection for email sub-scans
    if email_details and email_details.sub_scans:
        for sub in email_details.sub_scans:
            if sub.verdict == Verdict.MALICIOUS:
                malicious_votes += 1
                accumulated_points += 40.0
                breakdown.append(ScoringFactor(
                    source="Email Sub-Scan Cascade",
                    weight=1.0,
                    points_contributed=40.0,
                    reason=f"Malicious embedded item detected ({sub.ioc_type.value}: {sub.indicator}): {sub.summary}",
                ))
            elif sub.verdict == Verdict.SUSPICIOUS:
                suspicious_votes += 1
                accumulated_points += 20.0
                breakdown.append(ScoringFactor(
                    source="Email Sub-Scan Cascade",
                    weight=0.8,
                    points_contributed=20.0,
                    reason=f"Suspicious embedded item ({sub.ioc_type.value}: {sub.indicator}): {sub.summary}",
                ))

    # Normalize final score between 0.0 and 100.0
    if total_valid_sources == 0 and not email_details:
        final_score = 0.0
    elif max_possible_points > 0:
        raw_score = (accumulated_points / max_possible_points) * 100.0
        
        # Severe penalty boosts for multi-source consensus
        if malicious_votes >= 2:
            raw_score = max(raw_score, 85.0 + (malicious_votes * 3))
        elif malicious_votes == 1:
            raw_score = max(raw_score, 70.0)
        elif suspicious_votes >= 2:
            raw_score = max(raw_score, 50.0 + (suspicious_votes * 5))
        elif suspicious_votes == 1:
            raw_score = max(raw_score, 38.0)
            
        final_score = min(100.0, max(0.0, raw_score))
    else:
        final_score = 0.0

    final_score = round(final_score, 1)

    # Determine Verdict and Risk Level
    if final_score >= 65.0 or malicious_votes > 0:
        verdict = Verdict.MALICIOUS
        risk_level = RiskLevel.CRITICAL if final_score >= 80.0 else RiskLevel.HIGH
    elif final_score >= 30.0 or suspicious_votes > 0:
        verdict = Verdict.SUSPICIOUS
        risk_level = RiskLevel.MEDIUM if final_score >= 45.0 else RiskLevel.LOW
    elif clean_votes > 0 and final_score < 30.0:
        verdict = Verdict.CLEAN
        risk_level = RiskLevel.CLEAN
    else:
        verdict = Verdict.UNKNOWN
        risk_level = RiskLevel.UNKNOWN

    return ScanResponse(
        id=scan_id or str(uuid.uuid4()),
        indicator=classification.normalized,
        defanged_indicator=classification.defanged,
        type=classification.ioc_type,
        verdict=verdict,
        confidence_score=final_score,
        risk_level=risk_level,
        scoring_breakdown=breakdown,
        sources=sources,
        raw_data=raw_data,
        email_analysis=email_details,
        scanned_at=datetime.utcnow(),
        is_cached=is_cached,
        cached_from=cached_from,
    )
