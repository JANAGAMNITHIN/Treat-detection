import pytest
from app.models.schemas import IOCType
from app.services.classifier import classify_ioc, extract_bulk_iocs
from app.services.security import refang_ioc, defang_ioc, is_ssrf_risk_ip, is_ssrf_risk_url_or_domain

def test_classify_hashes():
    # MD5 (32 chars)
    res_md5 = classify_ioc("44d88612fea8a8f36de82e1278abb02f")
    assert res_md5.ioc_type == IOCType.MD5
    assert res_md5.normalized == "44d88612fea8a8f36de82e1278abb02f"

    # SHA1 (40 chars)
    res_sha1 = classify_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert res_sha1.ioc_type == IOCType.SHA1
    assert res_sha1.normalized == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    # SHA256 (64 chars)
    res_sha256 = classify_ioc("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert res_sha256.ioc_type == IOCType.SHA256
    assert res_sha256.normalized == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

def test_classify_ip_addresses():
    # IPv4 standard
    res_ip4 = classify_ioc("8.8.8.8")
    assert res_ip4.ioc_type == IOCType.IPV4
    assert res_ip4.normalized == "8.8.8.8"
    assert not res_ip4.is_defanged

    # IPv4 defanged
    res_ip4_defanged = classify_ioc("192[.]168[.]1[.]1")
    assert res_ip4_defanged.ioc_type == IOCType.IPV4
    assert res_ip4_defanged.normalized == "192.168.1.1"
    assert res_ip4_defanged.is_defanged

    # IPv6 standard
    res_ip6 = classify_ioc("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert res_ip6.ioc_type == IOCType.IPV6
    assert res_ip6.normalized == "2001:db8:85a3::8a2e:370:7334"

    # IPv6 bracketed
    res_ip6_brack = classify_ioc("[2001:db8::1]")
    assert res_ip6_brack.ioc_type == IOCType.IPV6
    assert res_ip6_brack.normalized == "2001:db8::1"

def test_classify_urls_and_defanged():
    # Standard HTTP URL
    res_url1 = classify_ioc("https://threat-intel.org/malware.exe")
    assert res_url1.ioc_type == IOCType.URL
    assert res_url1.normalized == "https://threat-intel.org/malware.exe"

    # Defanged URL (hxxp, brackets)
    res_url2 = classify_ioc("hxxps[://]evil-domain[.]com/drop/payload[.]bin")
    assert res_url2.ioc_type == IOCType.URL
    assert res_url2.normalized == "https://evil-domain.com/drop/payload.bin"
    assert res_url2.is_defanged

    # Implicit URL with path
    res_url3 = classify_ioc("bad-site.xyz/login.php?user=admin")
    assert res_url3.ioc_type == IOCType.URL
    assert res_url3.normalized == "https://bad-site.xyz/login.php?user=admin"

def test_classify_domains():
    # Domain standard
    res_dom = classify_ioc("phishing-target.co.uk")
    assert res_dom.ioc_type == IOCType.DOMAIN
    assert res_dom.normalized == "phishing-target.co.uk"

    # Domain defanged
    res_dom_defanged = classify_ioc("bad-actor[.]ru")
    assert res_dom_defanged.ioc_type == IOCType.DOMAIN
    assert res_dom_defanged.normalized == "bad-actor.ru"
    assert res_dom_defanged.is_defanged

def test_classify_emails():
    # Standard email
    res_email = classify_ioc("security-alert@paypal-update.com")
    assert res_email.ioc_type == IOCType.EMAIL
    assert res_email.normalized == "security-alert@paypal-update.com"

    # Defanged email
    res_email_defanged = classify_ioc("phisher[at]bad-domain[.]com")
    assert res_email_defanged.ioc_type == IOCType.EMAIL
    assert res_email_defanged.normalized == "phisher@bad-domain.com"
    assert res_email_defanged.is_defanged

def test_classify_email_headers():
    sample_header = """Received: from mail.attacker.com (mail.attacker.com [198.51.100.1])
Authentication-Results: mx.google.com; dkim=fail header.i=@legit.com; spf=fail (google.com: domain of spoof@legit.com does not designate 198.51.100.1 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=attacker.com;
From: "CEO John Doe" <spoof@legit.com>
Subject: Urgent Wire Transfer Request
Message-ID: <123456@attacker.com>"""
    
    res = classify_ioc(sample_header)
    assert res.ioc_type == IOCType.EMAIL_HEADER

def test_ssrf_protections():
    # Loopback
    is_risk, reason = is_ssrf_risk_ip("127.0.0.1")
    assert is_risk

    # RFC1918 Private
    is_risk_priv, _ = is_ssrf_risk_ip("192.168.1.50")
    assert is_risk_priv

    # Cloud Metadata
    is_risk_meta, _ = is_ssrf_risk_ip("169.254.169.254")
    assert is_risk_meta

    # Public IP should not be blocked
    is_risk_pub, _ = is_ssrf_risk_ip("8.8.8.8")
    assert not is_risk_pub

    # Localhost hostnames
    is_risk_host, _ = is_ssrf_risk_url_or_domain("http://localhost:8000/test")
    assert is_risk_host

    is_risk_meta_host, _ = is_ssrf_risk_url_or_domain("http://169.254.169.254/latest/meta-data")
    assert is_risk_meta_host

def test_extract_bulk_iocs():
    bulk_text = """8.8.8.8
192[.]168[.]1[.]1, 44d88612fea8a8f36de82e1278abb02f;
hxxps[://]evil[.]com/bad
bad-domain.org"""
    iocs = extract_bulk_iocs(bulk_text)
    assert len(iocs) == 5
    assert "8.8.8.8" in iocs
    assert "192[.]168[.]1[.]1" in iocs
    assert "44d88612fea8a8f36de82e1278abb02f" in iocs
