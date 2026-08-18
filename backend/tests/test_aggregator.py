import pytest
from app.models.schemas import (
    IOCClassification,
    IOCType,
    RiskLevel,
    SourceResult,
    Verdict,
)
from app.services.aggregator import aggregate_and_score

def test_aggregator_malicious_consensus():
    clf = IOCClassification(
        raw_input="test-malware.exe",
        normalized="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        defanged="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ioc_type=IOCType.SHA256,
    )

    sources = [
        SourceResult(
            name="VirusTotal",
            ioc_type=IOCType.SHA256,
            verdict=Verdict.MALICIOUS,
            confidence_score=92.0,
            summary="48/70 vendors flagged",
        ),
        SourceResult(
            name="MalwareBazaar (abuse.ch)",
            ioc_type=IOCType.SHA256,
            verdict=Verdict.MALICIOUS,
            confidence_score=100.0,
            summary="Confirmed RedLine sample",
        ),
    ]

    res = aggregate_and_score(clf, sources)
    assert res.verdict == Verdict.MALICIOUS
    assert res.confidence_score >= 85.0
    assert res.risk_level == RiskLevel.CRITICAL
    assert len(res.scoring_breakdown) == 2

def test_aggregator_clean_verdict():
    clf = IOCClassification(
        raw_input="8.8.8.8",
        normalized="8.8.8.8",
        defanged="8[.]8[.]8[.]8",
        ioc_type=IOCType.IPV4,
    )

    sources = [
        SourceResult(
            name="VirusTotal",
            ioc_type=IOCType.IPV4,
            verdict=Verdict.CLEAN,
            confidence_score=0.0,
            summary="0/90 engines flagged",
        ),
        SourceResult(
            name="AbuseIPDB",
            ioc_type=IOCType.IPV4,
            verdict=Verdict.CLEAN,
            confidence_score=0.0,
            summary="0% abuse score",
        ),
    ]

    res = aggregate_and_score(clf, sources)
    assert res.verdict == Verdict.CLEAN
    assert res.confidence_score < 30.0
    assert res.risk_level == RiskLevel.CLEAN

def test_aggregator_suspicious_verdict():
    clf = IOCClassification(
        raw_input="recently-created-domain.xyz",
        normalized="recently-created-domain.xyz",
        defanged="recently-created-domain[.]xyz",
        ioc_type=IOCType.DOMAIN,
    )

    sources = [
        SourceResult(
            name="WHOIS / RDAP",
            ioc_type=IOCType.DOMAIN,
            verdict=Verdict.SUSPICIOUS,
            confidence_score=45.0,
            summary="Domain registered 8 days ago",
        ),
        SourceResult(
            name="VirusTotal",
            ioc_type=IOCType.DOMAIN,
            verdict=Verdict.CLEAN,
            confidence_score=5.0,
            summary="0 engines flagged",
        ),
    ]

    res = aggregate_and_score(clf, sources)
    assert res.verdict == Verdict.SUSPICIOUS
    assert 30.0 <= res.confidence_score < 65.0
