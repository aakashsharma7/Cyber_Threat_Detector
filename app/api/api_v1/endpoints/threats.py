from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.session import get_db
from app.db.models import ThreatLog, User
from app.schemas.threat import ThreatLogCreate, ThreatLogResponse, ThreatAnalysis
from app.services.threat_analyzer import ThreatAnalyzer
from app.core.auth import get_current_user
from datetime import datetime, timedelta
import pytz

router = APIRouter()
threat_analyzer = ThreatAnalyzer()

@router.get("/", response_model=List[ThreatLogResponse])
def get_threats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    threat_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    resolved: Optional[bool] = None
):
    """Get list of detected threats"""
    query = db.query(ThreatLog)
    
    if threat_type:
        query = query.filter(ThreatLog.threat_type == threat_type)
    if start_date:
        query = query.filter(ThreatLog.timestamp >= start_date)
    if end_date:
        query = query.filter(ThreatLog.timestamp <= end_date)
    if resolved is not None:
        query = query.filter(ThreatLog.resolved == resolved)
        
    return query.offset(skip).limit(limit).all()

@router.post("/analyze", response_model=ThreatAnalysis)
def analyze_threat(
    threat_data: ThreatLogCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Analyze a potential threat"""
    try:
        # Convert Pydantic model to dict
        threat_dict = threat_data.model_dump()
        
        # Analyze the threat
        analysis = threat_analyzer.analyze(threat_dict)
        
        # Log the threat if it's detected
        if analysis.get("is_threat", False):
            threat_analyzer.log_threat(db, threat_dict, analysis)
            
        return analysis
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error analyzing threat: {str(e)}"
        )

@router.post("/{threat_id}/resolve")
def resolve_threat(
    threat_id: int,
    resolution_notes: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark a threat as resolved"""
    threat = db.query(ThreatLog).filter(ThreatLog.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
        
    threat.resolved = True
    threat.resolved_at = datetime.now(pytz.UTC)
    threat.resolved_by = current_user.id
    threat.resolution_notes = resolution_notes
    
    db.commit()
    return {"message": "Threat resolved successfully"}

@router.get("/stats")
def get_threat_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    days: int = Query(7, ge=1, le=30)
):
    """Get threat statistics"""
    start_date = datetime.now(pytz.UTC) - timedelta(days=days)
    
    # Get total threats
    total_threats = db.query(ThreatLog).filter(
        ThreatLog.timestamp >= start_date
    ).count()
    
    # Get threats by type
    threats_by_type = db.query(
        ThreatLog.threat_type,
        func.count(ThreatLog.id)
    ).filter(
        ThreatLog.timestamp >= start_date
    ).group_by(
        ThreatLog.threat_type
    ).all()
    
    # Get resolved threats
    resolved_threats = db.query(ThreatLog).filter(
        ThreatLog.timestamp >= start_date,
        ThreatLog.resolved == True
    ).count()
    
    return {
        "total_threats": total_threats,
        "threats_by_type": dict(threats_by_type),
        "resolved_threats": resolved_threats,
        "resolution_rate": resolved_threats / total_threats if total_threats > 0 else 0
    } 