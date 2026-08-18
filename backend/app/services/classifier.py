import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from app.models.schemas import IOCClassification, IOCType
from app.services.security import refang_ioc, defang_ioc

# Pre-compiled Regex Patterns for speed and reliability
MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_REGEX = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
URL_SCHEME_REGEX = re.compile(r'^(?:https?|ftp|sftp|ws|wss|hxxps?|h\*\*ps?|http\[s\]|fxps?)://', re.IGNORECASE)

# Valid Top Level Domain pattern (at least 2 letters, e.g. .com, .org, .xyz, .cloud, etc.)
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?::\d{1,5})?$'
)

# Email header signatures
EMAIL_HEADER_SIGNATURES = [
    "received:",
    "authentication-results:",
    "arc-authentication-results:",
    "dkim-signature:",
    "return-path:",
    "delivered-to:",
    "message-id:",
    "mime-version:",
    "content-type: multipart/",
    "content-transfer-encoding:"
]

def is_email_header(text: str) -> bool:
    """Detects whether raw multiline text represents raw email headers or an EML dump."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return False
        
    text_lower = text.lower()
    matches = sum(1 for sig in EMAIL_HEADER_SIGNATURES if sig in text_lower)
    
    # If 2 or more standard email header keywords are found, classify as email header
    return matches >= 2

def classify_ioc(raw_input: str) -> IOCClassification:
    """
    Classifies a raw string indicator into its appropriate IOCType,
    identifying if it was defanged and returning both refanged and defanged strings.
    """
    if not raw_input or not raw_input.strip():
        return IOCClassification(
            raw_input=raw_input,
            normalized="",
            defanged="",
            ioc_type=IOCType.UNKNOWN,
            confidence=0.0,
            notes="Empty input",
        )

    trimmed = raw_input.strip()
    
    # 1. Check if multiline email header
    if "\n" in trimmed and is_email_header(trimmed):
        return IOCClassification(
            raw_input=trimmed,
            normalized=trimmed,
            defanged=trimmed,
            ioc_type=IOCType.EMAIL_HEADER,
            is_defanged=False,
            confidence=1.0,
            notes="Detected raw email RFC 5322 header dump",
        )

    # Clean single-line tokens
    # Detect if user provided defanged patterns
    has_defang_markers = bool(
        re.search(r'\[\.\]|\(\.\)|\{\.\}|\\\.|\(dot\)|\[dot\]|\[@\]|\(@\)|\s*\[at\]\s*|hxxps?://|h\*\*ps?://|\[:\]', trimmed, re.IGNORECASE)
    )

    refanged = refang_ioc(trimmed)

    # 2. Check File Hashes (MD5, SHA1, SHA256)
    hash_candidate = refanged.lower().strip()
    if SHA256_REGEX.match(hash_candidate):
        return IOCClassification(
            raw_input=trimmed,
            normalized=hash_candidate,
            defanged=hash_candidate,
            ioc_type=IOCType.SHA256,
            is_defanged=False,
            confidence=1.0,
            notes="Standard 64-character SHA-256 hash",
        )
    if SHA1_REGEX.match(hash_candidate):
        return IOCClassification(
            raw_input=trimmed,
            normalized=hash_candidate,
            defanged=hash_candidate,
            ioc_type=IOCType.SHA1,
            is_defanged=False,
            confidence=1.0,
            notes="Standard 40-character SHA-1 hash",
        )
    if MD5_REGEX.match(hash_candidate):
        return IOCClassification(
            raw_input=trimmed,
            normalized=hash_candidate,
            defanged=hash_candidate,
            ioc_type=IOCType.MD5,
            is_defanged=False,
            confidence=1.0,
            notes="Standard 32-character MD5 hash",
        )

    # 3. Check IPv4 & IPv6 Addresses
    # Try parsing directly with ipaddress
    ip_candidate = refanged.split(":")[0] if ":" in refanged and not refanged.startswith("http") and "." in refanged else refanged
    # Handle port e.g. 192.168.1.1:8080
    clean_ip_str = ip_candidate.strip("[]")
    
    try:
        ip_obj = ipaddress.ip_address(clean_ip_str)
        ioc_type = IOCType.IPV4 if ip_obj.version == 4 else IOCType.IPV6
        return IOCClassification(
            raw_input=trimmed,
            normalized=str(ip_obj),
            defanged=defang_ioc(str(ip_obj), ioc_type.value),
            ioc_type=ioc_type,
            is_defanged=has_defang_markers,
            confidence=1.0,
            notes=f"Valid IPv{ip_obj.version} address",
        )
    except ValueError:
        pass

    # 4. Check Email Address
    if EMAIL_REGEX.match(refanged) and not ("/" in refanged or "://" in refanged):
        return IOCClassification(
            raw_input=trimmed,
            normalized=refanged.lower(),
            defanged=defang_ioc(refanged.lower(), "email"),
            ioc_type=IOCType.EMAIL,
            is_defanged=has_defang_markers,
            confidence=1.0,
            notes="Valid email address",
        )

    # 5. Check URL
    if URL_SCHEME_REGEX.match(trimmed) or URL_SCHEME_REGEX.match(refanged):
        # Ensure scheme is valid
        parsed = urlparse(refanged)
        if parsed.scheme and parsed.netloc:
            return IOCClassification(
                raw_input=trimmed,
                normalized=refanged,
                defanged=defang_ioc(refanged, "url"),
                ioc_type=IOCType.URL,
                is_defanged=has_defang_markers,
                confidence=1.0,
                notes="Explicit URL with protocol scheme",
            )

    # If it contains a slash or query params or path (e.g. evil.com/login.php or bit.ly/3xyz)
    if "/" in refanged and not refanged.startswith("http"):
        # Check if prepending https:// makes it a valid URL
        test_url = "https://" + refanged
        parsed = urlparse(test_url)
        if parsed.netloc and DOMAIN_REGEX.match(parsed.netloc):
            return IOCClassification(
                raw_input=trimmed,
                normalized=test_url,
                defanged=defang_ioc(test_url, "url"),
                ioc_type=IOCType.URL,
                is_defanged=has_defang_markers,
                confidence=0.95,
                notes="Implicit URL with host and path",
            )

    # 6. Check Domain
    # Remove port if present for domain checking e.g. malicious.com:8443
    domain_candidate = refanged.split(":")[0].lower()
    if DOMAIN_REGEX.match(domain_candidate):
        return IOCClassification(
            raw_input=trimmed,
            normalized=domain_candidate,
            defanged=defang_ioc(domain_candidate, "domain"),
            ioc_type=IOCType.DOMAIN,
            is_defanged=has_defang_markers,
            confidence=0.98,
            notes="Fully Qualified Domain Name",
        )

    # 7. Fallback: Unknown
    return IOCClassification(
        raw_input=trimmed,
        normalized=refanged,
        defanged=trimmed,
        ioc_type=IOCType.UNKNOWN,
        is_defanged=False,
        confidence=0.0,
        notes="Unrecognized indicator format",
    )

def extract_bulk_iocs(text: str) -> List[str]:
    """
    Extracts individual IOC strings from bulk multiline, CSV, or whitespace-delimited text.
    Filters out empty tokens.
    """
    if not text:
        return []
        
    # If it's an email header, treat the entire dump as a single entity
    if is_email_header(text):
        return [text.strip()]

    # Split on newlines, commas, semicolons, tabs, and spaces (when not within an email header)
    tokens = re.split(r'[\r\n,;\t]+', text)
    result = []
    
    for token in tokens:
        cleaned = token.strip().strip("\"'<>")
        if cleaned and not cleaned.startswith("#"):
            result.append(cleaned)
            
    return result
