import asyncio
import csv
from datetime import datetime
import io
import time
from typing import List, Optional
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import (
    get_db,
    async_session_factory,
    get_cached_scan,
    save_scan_record,
    get_scan_history,
    get_scan_by_id,
    delete_all_history,
    set_db_api_key,
)
from app.models.schemas import (
    ApiKeyStatus,
    BulkScanItemResult,
    BulkScanRequest,
    BulkScanResponse,
    HealthResponse,
    IOCClassification,
    IOCType,
    RiskLevel,
    ScanRequest,
    ScanResponse,
    SettingsResponse,
    UpdateKeysRequest,
    Verdict,
)
from app.services.aggregator import aggregate_and_score
from app.services.analyzers.dispatcher import dispatch_analysis, get_active_api_keys
from app.services.classifier import classify_ioc, extract_bulk_iocs
from app.services.security import is_ssrf_risk_ip, is_ssrf_risk_url_or_domain

router = APIRouter(prefix="/api")

@router.get("/health", response_model=HealthResponse)
async def health_check(session: AsyncSession = Depends(get_db)):
    keys = await get_active_api_keys(session)
    configured = [k for k, v in keys.items() if v]
    return HealthResponse(
        status="healthy",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        database="sqlite_active",
        configured_providers=configured,
        timestamp=datetime.utcnow(),
    )

@router.post("/classify", response_model=IOCClassification)
async def classify_indicator(req: ScanRequest):
    return classify_ioc(req.indicator)

@router.post("/scan", response_model=ScanResponse)
async def scan_single_ioc(
    req: ScanRequest,
    session: AsyncSession = Depends(get_db)
):
    """
    Scans a single IOC (URL, IP, Domain, Hash, Email, or Email Header).
    Checks cache first (unless force_refresh is True), validates SSRF risks,
    queries active threat intel providers, and aggregates risk score.
    """
    raw_input = req.indicator.strip()
    if not raw_input:
        raise HTTPException(status_code=400, detail="Indicator cannot be empty.")

    clf = classify_ioc(raw_input)
    if clf.ioc_type == IOCType.UNKNOWN:
        raise HTTPException(
            status_code=422,
            detail="Unrecognized Indicator of Compromise format. Please supply a valid URL, Domain, IP, File Hash, or Email.",
        )

    # SSRF Protection Check
    if clf.ioc_type in [IOCType.IPV4, IOCType.IPV6]:
        is_risk, reason = is_ssrf_risk_ip(clf.normalized)
        if is_risk:
            raise HTTPException(
                status_code=400,
                detail=f"Security rejection: Scan blocked by SSRF protection policy. ({reason})",
            )
    elif clf.ioc_type in [IOCType.URL, IOCType.DOMAIN]:
        is_risk, reason = is_ssrf_risk_url_or_domain(clf.normalized)
        if is_risk:
            raise HTTPException(
                status_code=400,
                detail=f"Security rejection: Scan blocked by SSRF protection policy. ({reason})",
            )

    # Cache Check
    if not req.force_refresh and clf.ioc_type != IOCType.EMAIL_HEADER:
        cached_record = await get_cached_scan(session, clf.normalized)
        if cached_record:
            rec_dict = cached_record.to_dict()
            return ScanResponse(
                id=rec_dict["id"],
                indicator=rec_dict["indicator"],
                defanged_indicator=rec_dict["defanged_indicator"],
                type=IOCType(rec_dict["type"]),
                verdict=Verdict(rec_dict["verdict"]),
                confidence_score=rec_dict["confidence_score"],
                risk_level=RiskLevel(rec_dict["risk_level"]),
                scoring_breakdown=rec_dict["scoring_breakdown"],
                sources=rec_dict["sources"],
                raw_data=rec_dict["raw_data"],
                email_analysis=rec_dict["email_analysis"],
                scanned_at=datetime.fromisoformat(rec_dict["scanned_at"]),
                is_cached=True,
                cached_from=datetime.fromisoformat(rec_dict["scanned_at"]),
            )

    # Dispatch to Threat Intel Providers
    sources, email_details = await dispatch_analysis(
        indicator=clf.normalized,
        ioc_type=clf.ioc_type,
        session=session,
        cascade_depth=1,
    )

    # Score Aggregation
    response = aggregate_and_score(
        classification=clf,
        sources=sources,
        email_details=email_details,
        is_cached=False,
    )

    # Save to SQLite
    if clf.ioc_type != IOCType.EMAIL_HEADER or len(clf.normalized) < 20000:
        await save_scan_record(session, response, ttl_hours=settings.CACHE_TTL_HOURS)

    return response

@router.post("/scan/file", response_model=ScanResponse)
async def scan_file_upload(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_db),
):
    """
    Computes cryptographic hashes of an uploaded file and scans against
    VirusTotal, MalwareBazaar, and other threat intelligence feeds.
    """
    import hashlib
    contents = await file.read()
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    md5_hash = hashlib.md5(contents).hexdigest()
    sha1_hash = hashlib.sha1(contents).hexdigest()
    sha256_hash = hashlib.sha256(contents).hexdigest()

    clf = IOCClassification(
        raw_input=file.filename or "uploaded_file",
        normalized=sha256_hash,
        defanged=sha256_hash,
        ioc_type=IOCType.SHA256,
        is_defanged=False,
        confidence=1.0,
        notes=f"File: {file.filename} ({len(contents)} bytes, MD5: {md5_hash})",
    )

    # Check cache for SHA-256
    cached_record = await get_cached_scan(session, sha256_hash)
    if cached_record:
        rec_dict = cached_record.to_dict()
        return ScanResponse(
            id=rec_dict["id"],
            indicator=rec_dict["indicator"],
            defanged_indicator=rec_dict["defanged_indicator"],
            type=IOCType(rec_dict["type"]),
            verdict=Verdict(rec_dict["verdict"]),
            confidence_score=rec_dict["confidence_score"],
            risk_level=RiskLevel(rec_dict["risk_level"]),
            scoring_breakdown=rec_dict["scoring_breakdown"],
            sources=rec_dict["sources"],
            raw_data=rec_dict["raw_data"],
            email_analysis=rec_dict["email_analysis"],
            scanned_at=datetime.fromisoformat(rec_dict["scanned_at"]),
            is_cached=True,
            cached_from=datetime.fromisoformat(rec_dict["scanned_at"]),
        )

    sources, email_details = await dispatch_analysis(
        indicator=sha256_hash,
        ioc_type=IOCType.SHA256,
        session=session,
    )

    response = aggregate_and_score(
        classification=clf,
        sources=sources,
        email_details=None,
        is_cached=False,
    )
    response.raw_data["file_meta"] = {
        "filename": file.filename,
        "file_size": len(contents),
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
    }

    await save_scan_record(session, response, ttl_hours=settings.CACHE_TTL_HOURS)
    return response

@router.post("/scan/bulk", response_model=BulkScanResponse)
async def scan_bulk_iocs(
    req: BulkScanRequest
):
    """
    Executes high-throughput bulk multi-IOC scans with concurrency control.
    Accepts multiline text, CSV strings, or explicit list of indicators.
    """
    start_time = time.perf_counter()
    
    indicators = []
    if req.indicators:
        indicators = [i.strip() for i in req.indicators if i.strip()]
    elif req.content:
        indicators = extract_bulk_iocs(req.content)

    if not indicators:
        raise HTTPException(status_code=400, detail="No valid indicators provided in bulk payload.")

    if len(indicators) > settings.MAX_BULK_IOCS:
        raise HTTPException(
            status_code=400,
            detail=f"Bulk scan size exceeds maximum allowed ({settings.MAX_BULK_IOCS} IOCs).",
        )

    semaphore = asyncio.Semaphore(5)

    async def _scan_single_bulk(index: int, item: str) -> BulkScanItemResult:
        async with semaphore:
            async with async_session_factory() as session:
                clf = classify_ioc(item)
                if clf.ioc_type == IOCType.UNKNOWN:
                    return BulkScanItemResult(
                        index=index,
                        indicator=item,
                        defanged=item,
                        ioc_type=IOCType.UNKNOWN,
                        verdict=Verdict.UNKNOWN,
                        confidence_score=0.0,
                        risk_level=RiskLevel.UNKNOWN,
                        sources_count=0,
                        scanned_at=datetime.utcnow(),
                        is_cached=False,
                    )

                # Cache check
                if not req.force_refresh:
                    cached = await get_cached_scan(session, clf.normalized)
                    if cached:
                        return BulkScanItemResult(
                            index=index,
                            indicator=cached.indicator,
                            defanged=cached.defanged_indicator,
                            ioc_type=IOCType(cached.ioc_type),
                            verdict=Verdict(cached.verdict),
                            confidence_score=cached.confidence_score,
                            risk_level=RiskLevel(cached.risk_level),
                            sources_count=len(cached.to_dict().get("sources", [])),
                            scanned_at=cached.scanned_at,
                            is_cached=True,
                        )

                sources, email_details = await dispatch_analysis(
                    indicator=clf.normalized,
                    ioc_type=clf.ioc_type,
                    session=session,
                    cascade_depth=0,
                )

                res = aggregate_and_score(
                    classification=clf,
                    sources=sources,
                    email_details=email_details,
                    is_cached=False,
                )

                await save_scan_record(session, res, ttl_hours=settings.CACHE_TTL_HOURS)

                return BulkScanItemResult(
                    index=index,
                    indicator=res.indicator,
                    defanged=res.defanged_indicator,
                    ioc_type=res.type,
                    verdict=res.verdict,
                    confidence_score=res.confidence_score,
                    risk_level=res.risk_level,
                    sources_count=len(res.sources),
                    scanned_at=res.scanned_at,
                    is_cached=False,
                )

    tasks = [_scan_single_bulk(i, ind) for i, ind in enumerate(indicators)]
    batch_results = await asyncio.gather(*tasks)

    malicious_c = sum(1 for r in batch_results if r.verdict == Verdict.MALICIOUS)
    suspicious_c = sum(1 for r in batch_results if r.verdict == Verdict.SUSPICIOUS)
    clean_c = sum(1 for r in batch_results if r.verdict == Verdict.CLEAN)
    unknown_c = sum(1 for r in batch_results if r.verdict == Verdict.UNKNOWN)

    duration = round(time.perf_counter() - start_time, 2)

    return BulkScanResponse(
        total=len(batch_results),
        malicious_count=malicious_c,
        suspicious_count=suspicious_c,
        clean_count=clean_c,
        unknown_count=unknown_c,
        results=batch_results,
        duration_seconds=duration,
    )

@router.get("/history")
async def get_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ioc_type: Optional[str] = Query("all"),
    verdict: Optional[str] = Query("all"),
    search: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_db),
):
    records, total = await get_scan_history(
        session=session,
        limit=limit,
        offset=offset,
        ioc_type=ioc_type,
        verdict=verdict,
        search=search,
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "records": [r.to_dict() for r in records],
    }

@router.get("/history/export")
async def export_history_csv(session: AsyncSession = Depends(get_db)):
    records, _ = await get_scan_history(session=session, limit=1000, offset=0)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID",
        "Indicator",
        "Defanged Indicator",
        "Type",
        "Verdict",
        "Confidence Score",
        "Risk Level",
        "Scanned At (UTC)",
    ])
    
    for r in records:
        writer.writerow([
            r.id,
            r.indicator,
            r.defanged_indicator,
            r.ioc_type,
            r.verdict,
            r.confidence_score,
            r.risk_level,
            r.scanned_at.isoformat() if r.scanned_at else "",
        ])
        
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatscope_scan_history.csv"}
    )

@router.get("/history/{scan_id}")
async def get_history_detail(scan_id: str, session: AsyncSession = Depends(get_db)):
    record = await get_scan_by_id(session, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return record.to_dict()

@router.delete("/history")
async def clear_history(session: AsyncSession = Depends(get_db)):
    await delete_all_history(session)
    return {"status": "success", "message": "Scan history cleared successfully."}

@router.get("/settings", response_model=SettingsResponse)
async def get_settings_status(session: AsyncSession = Depends(get_db)):
    keys = await get_active_api_keys(session)
    statuses = [
        ApiKeyStatus(
            name="VirusTotal",
            configured=bool(keys.get("virustotal")),
            description="Multi-engine scanner for Hashes, URLs, Domains, and IPs",
            free_tier_info="Free tier: 4 requests/min, 500 requests/day",
        ),
        ApiKeyStatus(
            name="AbuseIPDB",
            configured=bool(keys.get("abuseipdb")),
            description="IP blacklist & abuse reporting reputation dataset",
            free_tier_info="Free tier: 1,000 checks/day",
        ),
        ApiKeyStatus(
            name="URLScan.io",
            configured=bool(keys.get("urlscan")),
            description="Automated webpage sandbox & DOM reputation inspection",
            free_tier_info="Free tier: 5,000 searches/day",
        ),
        ApiKeyStatus(
            name="Google Safe Browsing",
            configured=bool(keys.get("safebrowsing")),
            description="Google blacklist for malware & phishing sites",
            free_tier_info="Free tier: 10,000 requests/day",
        ),
        ApiKeyStatus(
            name="MalwareBazaar",
            configured=bool(keys.get("malwarebazaar")),
            description="Abuse.ch repository of known malware samples and hashes",
            free_tier_info="Free public access (Optional Auth-Key for higher rates)",
        ),
        ApiKeyStatus(
            name="WHOIS / RDAP",
            configured=True,
            description="Public RDAP registry lookup for domain registration age & registrar",
            free_tier_info="Free public registry access (No API key required)",
        ),
    ]
    return SettingsResponse(
        keys=statuses,
        cache_ttl_hours=settings.CACHE_TTL_HOURS,
        app_version=settings.APP_VERSION,
    )

@router.post("/settings/keys")
async def update_api_keys(req: UpdateKeysRequest, session: AsyncSession = Depends(get_db)):
    if req.virustotal is not None:
        await set_db_api_key(session, "virustotal", req.virustotal.strip())
    if req.abuseipdb is not None:
        await set_db_api_key(session, "abuseipdb", req.abuseipdb.strip())
    if req.urlscan is not None:
        await set_db_api_key(session, "urlscan", req.urlscan.strip())
    if req.safebrowsing is not None:
        await set_db_api_key(session, "safebrowsing", req.safebrowsing.strip())
    if req.malwarebazaar is not None:
        await set_db_api_key(session, "malwarebazaar", req.malwarebazaar.strip())
    if req.shodan is not None:
        await set_db_api_key(session, "shodan", req.shodan.strip())
    if req.greynoise is not None:
        await set_db_api_key(session, "greynoise", req.greynoise.strip())

    return {"status": "success", "message": "API Keys updated successfully."}
