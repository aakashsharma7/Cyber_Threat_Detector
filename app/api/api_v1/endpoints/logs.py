from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, LoginAttempt
from app.services.log_scanner import LogScanner
from app.core.auth import get_current_active_user
from datetime import datetime, timedelta
import pytz

router = APIRouter()
log_scanner = LogScanner()

@router.get("/scan")
def scan_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    log_file: Optional[str] = None
):
    """Scan logs for suspicious activity"""
    try:
        log_entries = log_scanner.scan_logs(log_file)
        return {
            "message": "Log scan completed successfully",
            "entries_found": len(log_entries),
            "entries": log_entries
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error scanning logs: {str(e)}"
        )

@router.get("/login-attempts")
def get_login_attempts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = 0,
    limit: int = 100,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    ip_address: Optional[str] = None,
    username: Optional[str] = None,
    success: Optional[bool] = None
):
    """Get login attempt history"""
    query = db.query(LoginAttempt)
    
    if start_date:
        query = query.filter(LoginAttempt.timestamp >= start_date)
    if end_date:
        query = query.filter(LoginAttempt.timestamp <= end_date)
    if ip_address:
        query = query.filter(LoginAttempt.ip_address == ip_address)
    if username:
        query = query.filter(LoginAttempt.username == username)
    if success is not None:
        query = query.filter(LoginAttempt.success == success)
        
    total = query.count()
    attempts = query.order_by(LoginAttempt.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "attempts": attempts
    }

@router.get("/stats")
def get_log_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    days: int = Query(7, ge=1, le=30)
):
    """Get log statistics"""
    start_date = datetime.now(pytz.UTC) - timedelta(days=days)
    
    # Get total login attempts
    total_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.timestamp >= start_date
    ).count()
    
    # Get successful vs failed attempts
    successful_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.timestamp >= start_date,
        LoginAttempt.success == True
    ).count()
    
    failed_attempts = total_attempts - successful_attempts
    
    # Get attempts by IP
    attempts_by_ip = db.query(
        LoginAttempt.ip_address,
        func.count(LoginAttempt.id)
    ).filter(
        LoginAttempt.timestamp >= start_date
    ).group_by(
        LoginAttempt.ip_address
    ).all()
    
    return {
        "total_attempts": total_attempts,
        "successful_attempts": successful_attempts,
        "failed_attempts": failed_attempts,
        "success_rate": successful_attempts / total_attempts if total_attempts > 0 else 0,
        "attempts_by_ip": dict(attempts_by_ip)
    } 