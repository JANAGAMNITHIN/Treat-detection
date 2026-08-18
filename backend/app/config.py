import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

def get_default_db_url() -> str:
    # On Vercel serverless, root filesystem is read-only, write to /tmp
    if os.environ.get("VERCEL"):
        return "sqlite+aiosqlite:////tmp/threatscope.db"
    return "sqlite+aiosqlite:///./threatscope.db"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="allow"
    )

    APP_NAME: str = "ThreatScope"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server configuration
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = ["*"]
    
    # Database
    DATABASE_URL: str = get_default_db_url()
    
    # Caching
    CACHE_TTL_HOURS: int = 24  # 24 hours default cache
    
    # Threat Intelligence API Keys (Optional - fallbacks / mock responses provided when missing)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    SAFEBROWSING_API_KEY: Optional[str] = None
    MALWAREBAZAAR_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    GREYNOISE_API_KEY: Optional[str] = None
    
    # Rate Limiting & Timeouts
    REQUEST_TIMEOUT_SECONDS: float = 12.0
    MAX_BULK_IOCS: int = 100
    
    # SSRF Protection
    BLOCKED_IP_NETWORKS: List[str] = [
        "127.0.0.0/8",      # Loopback
        "10.0.0.0/8",       # Private RFC1918
        "172.16.0.0/12",    # Private RFC1918
        "192.168.0.0/16",   # Private RFC1918
        "169.254.0.0/16",   # Link-local / Cloud metadata (AWS, GCP, Azure)
        "::1/128",          # IPv6 Loopback
        "fc00::/7",         # IPv6 Unique Local
        "fe80::/10",        # IPv6 Link-Local
    ]

settings = Settings()
