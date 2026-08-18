from datetime import datetime
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import Column, String, Float, DateTime, Text, Index
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(String(64), primary_key=True, index=True)
    indicator = Column(String(1024), nullable=False, index=True)
    defanged_indicator = Column(String(1024), nullable=False)
    ioc_type = Column(String(32), nullable=False, index=True)
    verdict = Column(String(32), nullable=False, index=True)
    confidence_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String(32), nullable=False, default="UNKNOWN")
    scanned_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    
    # Serialized details
    scoring_breakdown_json = Column(Text, default="[]")
    sources_json = Column(Text, default="[]")
    raw_data_json = Column(Text, default="{}")
    email_analysis_json = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_indicator_expires", "indicator", "expires_at"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "indicator": self.indicator,
            "defanged_indicator": self.defanged_indicator,
            "type": self.ioc_type,
            "verdict": self.verdict,
            "confidence_score": self.confidence_score,
            "risk_level": self.risk_level,
            "scoring_breakdown": json.loads(self.scoring_breakdown_json or "[]"),
            "sources": json.loads(self.sources_json or "[]"),
            "raw_data": json.loads(self.raw_data_json or "{}"),
            "email_analysis": json.loads(self.email_analysis_json) if self.email_analysis_json else None,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }

class ApiKeyStorage(Base):
    __tablename__ = "api_keys"

    key_name = Column(String(64), primary_key=True)
    key_value = Column(String(512), nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
