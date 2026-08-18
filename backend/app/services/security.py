import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse
from app.config import settings

def refang_ioc(indicator: str) -> str:
    """
    Normalizes defanged indicators (e.g. hxxps://, 192[.]168[.]1[.]1, test[at]domain[.]com)
    into standard actionable format for API queries.
    """
    if not indicator:
        return ""
    
    cleaned = indicator.strip()
    
    # Refang scheme
    cleaned = re.sub(r'(?i)^hxxps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', cleaned)
    cleaned = re.sub(r'(?i)^hxxp\[:\]//', lambda m: 'http://', cleaned)
    cleaned = re.sub(r'(?i)^hxxps\[:\]//', lambda m: 'https://', cleaned)
    cleaned = re.sub(r'(?i)^hxxp\[://\]', lambda m: 'http://', cleaned)
    cleaned = re.sub(r'(?i)^hxxps\[://\]', lambda m: 'https://', cleaned)
    cleaned = re.sub(r'(?i)^h\*\*ps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', cleaned)
    cleaned = re.sub(r'(?i)^http\[s\]://', 'https://', cleaned)
    cleaned = re.sub(r'(?i)^https?\[://\]', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', cleaned)
    cleaned = re.sub(r'(?i)^https?\[:\]//', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', cleaned)
    cleaned = re.sub(r'(?i)^ftp\[:\]//', 'ftp://', cleaned)
    cleaned = re.sub(r'(?i)^fxp\[:\]//', 'ftp://', cleaned)
    cleaned = re.sub(r'(?i)^fxps?://', 'ftp://', cleaned)

    # Refang brackets around dots
    cleaned = re.sub(r'\[\.\]|\(\.\)|\{\.\}|\\\.|\s*\(dot\)\s*|\s*\[dot\]\s*', '.', cleaned, flags=re.IGNORECASE)

    # Refang brackets around colons (ports, IPv6)
    cleaned = re.sub(r'\[:\]|\(:\)|\{:\}', ':', cleaned)

    # Refang brackets around at sign
    cleaned = re.sub(r'\[@\]|\(@\)|\{@\}|\s*\[at\]\s*|\s*\(at\)\s*', '@', cleaned, flags=re.IGNORECASE)

    # Clean leading/trailing quotes or brackets
    cleaned = cleaned.strip("\"'<>[]()")
    
    return cleaned

def defang_ioc(indicator: str, ioc_type: Optional[str] = None) -> str:
    """
    Safely defangs an indicator so it cannot be accidentally resolved, clicked, or executed.
    Example:
    http://malicious.com/bad -> hxxp[://]malicious[.]com/bad
    192.168.1.1 -> 192[.]168[.]1[.]1
    user@domain.com -> user[@]domain[.]com
    """
    if not indicator:
        return ""
    
    defanged = indicator.strip()
    
    # Handle scheme
    if defanged.lower().startswith("https://"):
        defanged = "hxxps[://]" + defanged[8:]
    elif defanged.lower().startswith("http://"):
        defanged = "hxxp[://]" + defanged[7:]
    elif defanged.lower().startswith("ftp://"):
        defanged = "fxp[://]" + defanged[6:]
        
    # Defang @ symbol for emails
    defanged = defanged.replace("@", "[@]")
    
    # Defang remaining dots (unless already defanged)
    # Avoid double defanging
    if "[.]" not in defanged and "(.)" not in defanged:
        defanged = defanged.replace(".", "[.]")
        
    return defanged

def is_ssrf_risk_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an IP address belongs to a private, loopback, link-local,
    or internal cloud metadata network to prevent SSRF vulnerabilities.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        
        # Check standard Python flags
        if ip_obj.is_loopback:
            return True, "Loopback address (127.0.0.0/8 or ::1)"
        if ip_obj.is_private:
            return True, "Private RFC1918 address"
        if ip_obj.is_link_local:
            return True, "Link-local address (169.254.0.0/16 or fe80::/10)"
        if ip_obj.is_reserved:
            return True, "Reserved IP space"
        if ip_obj.is_multicast:
            return True, "Multicast address"
            
        # Check custom blocked networks from settings
        for blocked_net in settings.BLOCKED_IP_NETWORKS:
            try:
                network = ipaddress.ip_network(blocked_net, strict=False)
                if ip_obj in network:
                    return True, f"IP belongs to blocked internal CIDR: {blocked_net}"
            except ValueError:
                continue
                
        return False, None
    except ValueError:
        # Not a valid IP string
        return False, None

def is_ssrf_risk_url_or_domain(target: str) -> Tuple[bool, Optional[str]]:
    """
    Validates hostnames/URLs to prevent SSRF against localhost, metadata services, etc.
    """
    try:
        refanged = refang_ioc(target)
        if "://" in refanged:
            parsed = urlparse(refanged)
            hostname = parsed.hostname or ""
        else:
            hostname = refanged.split("/")[0].split(":")[0]
            
        hostname_clean = hostname.strip().lower()
        
        # Obvious localhost aliases
        localhost_names = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal", "169.254.169.254", "instance-data"]
        if hostname_clean in localhost_names:
            return True, f"Target host '{hostname_clean}' is a restricted local or cloud metadata address."
            
        # Check if hostname is an IP literal
        try:
            ip_obj = ipaddress.ip_address(hostname_clean)
            is_risk, reason = is_ssrf_risk_ip(str(ip_obj))
            if is_risk:
                return True, reason
        except ValueError:
            pass
            
        return False, None
    except Exception as e:
        return False, None
