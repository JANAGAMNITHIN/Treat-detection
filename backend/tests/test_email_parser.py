import pytest
from app.models.schemas import IOCType, Verdict
from app.services.analyzers.email_parser import EmailHeaderAnalyzer

SAMPLE_SPOOFED_EMAIL = """Received: from mail.bad-attacker.net ([198.51.100.24])
Authentication-Results: mx.google.com;
       dkim=fail header.i=@target-bank.com;
       spf=fail (google.com: domain of alert@target-bank.com does not designate 198.51.100.24 as permitted sender)
       dmarc=fail (p=REJECT)
Return-Path: <bounce@bad-attacker.net>
From: "Security Center" <alert@target-bank.com>
Subject: Urgent: Your account has been suspended
Date: Mon, 12 Aug 2026 10:15:00 +0000
Message-ID: <evil-12345@bad-attacker.net>
Content-Type: text/plain

Please verify your credentials immediately at hxxps[://]verify-login[.]phish-portal[.]com/auth.
"""

def test_email_spoof_detection():
    analyzer = EmailHeaderAnalyzer()
    details = analyzer.parse_email_text(SAMPLE_SPOOFED_EMAIL)

    assert "alert@target-bank.com" in details.from_address
    assert "bounce@bad-attacker.net" in details.return_path
    assert details.spf_status == "FAIL"
    assert details.dkim_status == "FAIL"
    assert details.dmarc_status == "FAIL"
    assert details.spoof_risk is True
    assert len(details.extracted_urls) >= 1
    assert "https://verify-login.phish-portal.com/auth" in details.extracted_urls

@pytest.mark.asyncio
async def test_email_analyzer_execution():
    analyzer = EmailHeaderAnalyzer()
    res = await analyzer.analyze(SAMPLE_SPOOFED_EMAIL, IOCType.EMAIL_HEADER)
    assert res.verdict in [Verdict.MALICIOUS, Verdict.SUSPICIOUS]
    assert res.confidence_score >= 50.0
