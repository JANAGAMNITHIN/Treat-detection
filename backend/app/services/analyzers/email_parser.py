import email
from email import policy
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.models.schemas import (
    EmailHeaderDetails,
    IOCType,
    SourceResult,
    SubScanItem,
    Verdict,
)
from app.services.analyzers.base import BaseAnalyzer
from app.services.security import refang_ioc

URL_REGEX = re.compile(
    r'(?:https?|ftp|hxxps?|h\*\*ps?|http\[s\]|fxps?)(?::\/\/|\[:\/\/?\]|\[:\]\/\/|\[:\/\/\])[^\s<>"\'\)]+',
    re.IGNORECASE
)

class EmailHeaderAnalyzer(BaseAnalyzer):
    name: str = "Email Header & MIME Inspector"
    supported_types = [IOCType.EMAIL, IOCType.EMAIL_HEADER]

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key=api_key or "N/A")

    def _parse_authentication_results(self, msg: email.message.Message) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract SPF, DKIM, and DMARC verdicts from Authentication-Results headers."""
        auth_headers = msg.get_all("Authentication-Results") or []
        arc_headers = msg.get_all("ARC-Authentication-Results") or []
        received_spf = msg.get_all("Received-SPF") or []

        spf = None
        dkim = None
        dmarc = None

        combined_text = " ".join(auth_headers + arc_headers + received_spf).lower()

        # SPF matching
        if "spf=pass" in combined_text or "pass (google.com:" in combined_text:
            spf = "PASS"
        elif "spf=fail" in combined_text:
            spf = "FAIL"
        elif "spf=softfail" in combined_text:
            spf = "SOFTFAIL"
        elif "spf=neutral" in combined_text:
            spf = "NEUTRAL"
        elif "spf=none" in combined_text:
            spf = "NONE"

        # DKIM matching
        if "dkim=pass" in combined_text:
            dkim = "PASS"
        elif "dkim=fail" in combined_text:
            dkim = "FAIL"
        elif "dkim=none" in combined_text:
            dkim = "NONE"

        # DMARC matching
        if "dmarc=pass" in combined_text:
            dmarc = "PASS"
        elif "dmarc=fail" in combined_text:
            dmarc = "FAIL"
        elif "dmarc=none" in combined_text:
            dmarc = "NONE"

        return spf, dkim, dmarc

    def _detect_spoofing(self, from_hdr: str, return_path: str, spf: Optional[str], dkim: Optional[str]) -> Tuple[bool, str]:
        """Detect sender impersonation and spoofing attempts."""
        if not from_hdr:
            return False, "No From address found"

        from_domain = from_hdr.split("@")[-1].strip(">").lower() if "@" in from_hdr else ""
        return_domain = return_path.split("@")[-1].strip(">").lower() if return_path and "@" in return_path else ""

        reasons = []
        is_spoof = False

        if return_domain and from_domain and return_domain != from_domain:
            reasons.append(f"Domain mismatch: From claims '{from_domain}', but Return-Path is '{return_domain}'")
            if spf == "FAIL" or dkim == "FAIL":
                is_spoof = True
                reasons.append("Email failed sender cryptographic authentication (SPF/DKIM fail).")

        if spf == "FAIL":
            is_spoof = True
            reasons.append("Sending mail server is not authorized to send for this domain (SPF FAIL).")

        if dkim == "FAIL":
            is_spoof = True
            reasons.append("Cryptographic digital signature is broken or tampered with (DKIM FAIL).")

        summary = "; ".join(reasons) if reasons else "No spoofing or authentication mismatches detected."
        return is_spoof, summary

    def _extract_urls_and_attachments(self, raw_content: str) -> Tuple[List[str], List[str], List[str]]:
        """Extract URLs, attachment names, and attachment hashes from raw email or text."""
        found_urls = set()
        
        # Regex matching for standard and defanged URLs
        for match in URL_REGEX.findall(raw_content):
            refanged = refang_ioc(match.strip(".,;\"'<>[]()"))
            if len(refanged) > 8:
                found_urls.add(refanged)

        attachment_names = []
        attachment_hashes = []

        try:
            msg = email.message_from_string(raw_content, policy=policy.default)
            for part in msg.walk():
                content_disposition = part.get_content_disposition()
                filename = part.get_filename()
                if content_disposition == "attachment" or filename:
                    file_name = filename or "unnamed_attachment"
                    attachment_names.append(file_name)
                    payload = part.get_payload(decode=True)
                    if payload:
                        sha256 = hashlib.sha256(payload).hexdigest()
                        attachment_hashes.append(sha256)
        except Exception:
            pass

        return list(found_urls), attachment_names, attachment_hashes

    def parse_email_text(self, text: str) -> EmailHeaderDetails:
        """Parse raw email header / EML text into structured EmailHeaderDetails."""
        try:
            msg = email.message_from_string(text, policy=policy.default)
            from_addr = str(msg.get("From", ""))
            return_path = str(msg.get("Return-Path", ""))
            subject = str(msg.get("Subject", ""))
            date_hdr = str(msg.get("Date", ""))
            msg_id = str(msg.get("Message-ID", ""))
        except Exception:
            from_addr = ""
            return_path = ""
            subject = ""
            date_hdr = ""
            msg_id = ""
            msg = email.message.Message()

        spf, dkim, dmarc = self._parse_authentication_results(msg)
        is_spoof, spoof_details = self._detect_spoofing(from_addr, return_path, spf, dkim)
        urls, att_names, att_hashes = self._extract_urls_and_attachments(text)

        return EmailHeaderDetails(
            from_address=from_addr or None,
            return_path=return_path or None,
            subject=subject or None,
            date=date_hdr or None,
            message_id=msg_id or None,
            spf_status=spf or "UNKNOWN",
            dkim_status=dkim or "UNKNOWN",
            dmarc_status=dmarc or "UNKNOWN",
            spoof_risk=is_spoof,
            spoof_details=spoof_details,
            extracted_urls=urls,
            extracted_hashes=att_hashes,
            attachment_names=att_names,
            sub_scans=[],
        )

    async def _scan_real(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        details = self.parse_email_text(indicator)
        
        score = 0.0
        reasons = []

        if details.spoof_risk:
            score += 45.0
            reasons.append("Sender spoofing / authentication failure detected")

        if details.spf_status == "FAIL":
            score += 25.0
            reasons.append("SPF validation failed")
        elif details.spf_status == "PASS":
            score -= 10.0

        if details.dkim_status == "FAIL":
            score += 25.0
            reasons.append("DKIM validation failed")
        elif details.dkim_status == "PASS":
            score -= 10.0

        if details.dmarc_status == "FAIL":
            score += 30.0
            reasons.append("DMARC policy failed")

        score = max(0.0, min(100.0, score))

        if score >= 60.0:
            verdict = Verdict.MALICIOUS
        elif score >= 25.0:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN if (details.spf_status == "PASS" or details.dkim_status == "PASS") else Verdict.UNKNOWN

        summary = f"SPF: {details.spf_status}, DKIM: {details.dkim_status}, DMARC: {details.dmarc_status}. "
        if reasons:
            summary += f"Flags: {', '.join(reasons)}."
        else:
            summary += "Header authentication is valid."

        return SourceResult(
            name=self.name,
            ioc_type=ioc_type,
            verdict=verdict,
            confidence_score=score,
            detail_url=None,
            summary=summary,
            raw_data=details.model_dump(),
            status="ok",
        )

    def _mock_response(self, indicator: str, ioc_type: IOCType) -> SourceResult:
        details = self.parse_email_text(indicator)
        return SourceResult(
            name=self.name,
            ioc_type=ioc_type,
            verdict=Verdict.MALICIOUS if details.spoof_risk else Verdict.CLEAN,
            confidence_score=75.0 if details.spoof_risk else 10.0,
            summary=f"SPF: {details.spf_status}, DKIM: {details.dkim_status}. Spoof risk: {details.spoof_risk}",
            raw_data=details.model_dump(),
            status="ok",
        )
