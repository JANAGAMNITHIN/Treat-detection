import json
from datetime import datetime, timedelta
from typing import AsyncGenerator, List, Optional, Tuple
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import select, desc, delete, func, or_

from app.config import settings
from app.models.db_models import Base, ScanRecord, ApiKeyStorage
from app.models.schemas import ScanResponse

# Async Database Engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

# Async Session Factory
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

async def init_db():
    """Initializes SQLite tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency yielding an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()

async def get_cached_scan(session: AsyncSession, indicator: str) -> Optional[ScanRecord]:
    """Retrieves a cached scan if it exists and has not expired."""
    now = datetime.utcnow()
    query = (
        select(ScanRecord)
        .where(ScanRecord.indicator == indicator)
        .where(ScanRecord.expires_at > now)
    )
    result = await session.execute(query)
    return result.scalar_one_or_none()

async def save_scan_record(session: AsyncSession, response: ScanResponse, ttl_hours: int = 24) -> Optional[ScanRecord]:
    """Saves or updates a scan response in SQLite."""
    now = datetime.utcnow()
    expires_at = now + timedelta(hours=ttl_hours)
    record_id = response.id or str(uuid4())

    breakdown_json = json.dumps([b.model_dump() for b in response.scoring_breakdown])
    sources_json = json.dumps([s.model_dump() for s in response.sources])
    raw_data_json = json.dumps(response.raw_data or {})
    email_json = json.dumps(response.email_analysis.model_dump()) if response.email_analysis else None

    try:
        query = select(ScanRecord).where(ScanRecord.indicator == response.indicator)
        result = await session.execute(query)
        existing = result.scalar_one_or_none()

        if existing:
            existing.id = record_id
            existing.defanged_indicator = response.defanged_indicator
            existing.ioc_type = response.type.value if hasattr(response.type, "value") else response.type
            existing.verdict = response.verdict.value if hasattr(response.verdict, "value") else response.verdict
            existing.confidence_score = response.confidence_score
            existing.risk_level = response.risk_level.value if hasattr(response.risk_level, "value") else response.risk_level
            existing.scanned_at = now
            existing.expires_at = expires_at
            existing.scoring_breakdown_json = breakdown_json
            existing.sources_json = sources_json
            existing.raw_data_json = raw_data_json
            existing.email_analysis_json = email_json
            record = existing
        else:
            record = ScanRecord(
                id=record_id,
                indicator=response.indicator,
                defanged_indicator=response.defanged_indicator,
                ioc_type=response.type.value if hasattr(response.type, "value") else response.type,
                verdict=response.verdict.value if hasattr(response.verdict, "value") else response.verdict,
                confidence_score=response.confidence_score,
                risk_level=response.risk_level.value if hasattr(response.risk_level, "value") else response.risk_level,
                scanned_at=now,
                expires_at=expires_at,
                scoring_breakdown_json=breakdown_json,
                sources_json=sources_json,
                raw_data_json=raw_data_json,
                email_analysis_json=email_json,
            )
            session.add(record)
        
        await session.commit()
        return record
    except Exception:
        await session.rollback()
        return None

async def get_scan_history(
    session: AsyncSession,
    limit: int = 50,
    offset: int = 0,
    ioc_type: Optional[str] = None,
    verdict: Optional[str] = None,
    search: Optional[str] = None,
) -> Tuple[List[ScanRecord], int]:
    """Get paginated scan history with optional filters."""
    query = select(ScanRecord)
    count_query = select(func.count(ScanRecord.id))
    
    if ioc_type and ioc_type != "all":
        query = query.where(ScanRecord.ioc_type == ioc_type)
        count_query = count_query.where(ScanRecord.ioc_type == ioc_type)
        
    if verdict and verdict != "all":
        query = query.where(ScanRecord.verdict == verdict)
        count_query = count_query.where(ScanRecord.verdict == verdict)
        
    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.where(ScanRecord.indicator.like(search_pattern))
        count_query = count_query.where(ScanRecord.indicator.like(search_pattern))

    total = (await session.execute(count_query)).scalar() or 0
    query = query.order_by(desc(ScanRecord.scanned_at)).offset(offset).limit(limit)
    records = (await session.execute(query)).scalars().all()
    return list(records), total

async def get_scan_by_id(session: AsyncSession, scan_id: str) -> Optional[ScanRecord]:
    """Get single scan record by ID or indicator."""
    query = select(ScanRecord).where(
        or_(
            ScanRecord.id == scan_id,
            ScanRecord.indicator == scan_id,
            ScanRecord.defanged_indicator == scan_id,
        )
    )
    result = await session.execute(query)
    return result.scalar_one_or_none()

async def delete_all_history(session: AsyncSession):
    await session.execute(delete(ScanRecord))
    await session.commit()

async def get_db_api_key(session: AsyncSession, key_name: str) -> Optional[str]:
    query = select(ApiKeyStorage).where(ApiKeyStorage.key_name == key_name)
    result = await session.execute(query)
    obj = result.scalar_one_or_none()
    return obj.key_value if obj else None

async def set_db_api_key(session: AsyncSession, key_name: str, key_value: str):
    query = select(ApiKeyStorage).where(ApiKeyStorage.key_name == key_name)
    result = await session.execute(query)
    obj = result.scalar_one_or_none()
    if obj:
        obj.key_value = key_value
        obj.updated_at = datetime.utcnow()
    else:
        obj = ApiKeyStorage(key_name=key_name, key_value=key_value)
        session.add(obj)
    await session.commit()
