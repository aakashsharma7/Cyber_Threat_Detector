from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from app.core.config import settings
from app.services.log_scanner import LogScanner
from app.services.threat_analyzer import ThreatAnalyzer
from app.db.session import SessionLocal
import logging

logger = logging.getLogger(__name__)

class ThreatScannerScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.log_scanner = LogScanner()
        self.threat_analyzer = ThreatAnalyzer()

    def start(self):
        """Start the scheduler"""
        try:
            # Add the scan job
            self.scheduler.add_job(
                self.scan_for_threats,
                trigger=IntervalTrigger(minutes=settings.SCAN_INTERVAL_MINUTES),
                id='threat_scan',
                name='Scan for threats',
                replace_existing=True
            )
            
            # Start the scheduler
            self.scheduler.start()
            logger.info("Threat scanner scheduler started successfully")
        except Exception as e:
            logger.error(f"Error starting scheduler: {str(e)}")
            raise

    def shutdown(self):
        """Shutdown the scheduler"""
        try:
            self.scheduler.shutdown()
            logger.info("Threat scanner scheduler shut down successfully")
        except Exception as e:
            logger.error(f"Error shutting down scheduler: {str(e)}")

    def scan_for_threats(self):
        """Perform a threat scan"""
        try:
            # Get database session
            db = SessionLocal()
            
            try:
                # Scan logs
                log_entries = self.log_scanner.scan_logs()
                
                # Analyze threats
                for entry in log_entries:
                    threat_analysis = self.threat_analyzer.analyze(entry)
                    
                    if threat_analysis["is_threat"]:
                        # Log the threat
                        self.threat_analyzer.log_threat(db, entry, threat_analysis)
                        
                        # Send alert if needed
                        if threat_analysis["threat_probability"] > 0.95:
                            self.threat_analyzer.send_alert(entry, threat_analysis)
            
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"Error during threat scan: {str(e)}")

# Create global scheduler instance
scheduler = ThreatScannerScheduler() 