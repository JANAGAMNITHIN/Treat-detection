from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class IOCType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    EMAIL_HEADER = "email_header"
    UNKNOWN = "unknown"

class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"

class IOCClassification(BaseModel):
    raw_input: str
    normalized: str
    defanged: str
    ioc_type: IOCType
    is_defanged: bool = False
    confidence: float = 1.0
    notes: Optional[str] = None

class SourceResult(BaseModel):
    name: str
    ioc_type: IOCType
    verdict: Verdict
    confidence_score: float = Field(ge=0.0, le=100.0, default=0.0)
    detail_url: Optional[str] = None
    summary: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0
    status: str = "ok"  # "ok", "mocked", "rate_limited", "error", "skipped"
    error_message: Optional[str] = None

class ScoringFactor(BaseModel):
    source: str
    weight: float
    points_contributed: float
    reason: str

class SubScanItem(BaseModel):
    indicator: str
    ioc_type: IOCType
    verdict: Verdict
    confidence_score: float
    summary: str

class EmailHeaderDetails(BaseModel):
    from_address: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    spf_status: Optional[str] = None
    dkim_status: Optional[str] = None
    dmarc_status: Optional[str] = None
    spoof_risk: bool = False
    spoof_details: Optional[str] = None
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_hashes: List[str] = Field(default_factory=list)
    attachment_names: List[str] = Field(default_factory=list)
    sub_scans: List[SubScanItem] = Field(default_factory=list)

class ScanRequest(BaseModel):
    indicator: str
    force_refresh: bool = False

class ScanResponse(BaseModel):
    id: Optional[str] = None
    indicator: str
    defanged_indicator: str
    type: IOCType
    verdict: Verdict
    confidence_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    scoring_breakdown: List[ScoringFactor] = Field(default_factory=list)
    sources: List[SourceResult] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    email_analysis: Optional[EmailHeaderDetails] = None
    scanned_at: datetime
    is_cached: bool = False
    cached_from: Optional[datetime] = None

class BulkScanRequest(BaseModel):
    content: Optional[str] = None  # Multiline or CSV text
    indicators: Optional[List[str]] = None
    force_refresh: bool = False

class BulkScanItemResult(BaseModel):
    index: int
    indicator: str
    defanged: str
    ioc_type: IOCType
    verdict: Verdict
    confidence_score: float
    risk_level: RiskLevel
    sources_count: int
    scanned_at: datetime
    is_cached: bool

class BulkScanResponse(BaseModel):
    total: int
    malicious_count: int
    suspicious_count: int
    clean_count: int
    unknown_count: int
    results: List[BulkScanItemResult]
    duration_seconds: float

class ApiKeyStatus(BaseModel):
    name: str
    configured: bool
    description: str
    free_tier_info: str

class SettingsResponse(BaseModel):
    keys: List[ApiKeyStatus]
    cache_ttl_hours: int
    app_version: str

class UpdateKeysRequest(BaseModel):
    virustotal: Optional[str] = None
    abuseipdb: Optional[str] = None
    urlscan: Optional[str] = None
    safebrowsing: Optional[str] = None
    malwarebazaar: Optional[str] = None
    shodan: Optional[str] = None
    greynoise: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str
    database: str
    configured_providers: List[str]
    timestamp: datetime
