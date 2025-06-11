from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class ThreatLogBase(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = None
    threat_type: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    details: Dict[str, Any]

class ThreatLogCreate(ThreatLogBase):
    pass

class ThreatLogResponse(ThreatLogBase):
    id: int
    timestamp: datetime
    is_false_positive: bool
    resolved: bool
    resolved_at: Optional[datetime]
    resolved_by: Optional[int]
    resolution_notes: Optional[str]

    class Config:
        from_attributes = True

class ThreatAnalysis(BaseModel):
    threat_probability: float = Field(..., ge=0.0, le=1.0)
    is_threat: bool
    is_blacklisted_ip: bool
    is_phishing_url: bool
    threat_type: str
    feature_importances: Dict[str, float]
    error: Optional[str] = None

class ThreatStats(BaseModel):
    total_threats: int
    threats_by_type: Dict[str, int]
    resolved_threats: int
    resolution_rate: float 