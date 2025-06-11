from typing import Dict, Any
import logging
import requests
from datetime import datetime
import pytz
from app.core.config import settings
from app.ml.threat_detector import ThreatDetector
from app.db.models import ThreatLog, IPBlacklist, PhishingURL
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    def __init__(self):
        self.threat_detector = ThreatDetector(settings.MODEL_PATH)
        self.virustotal_api_key = settings.VIRUSTOTAL_API_KEY

    def analyze(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a log entry for potential threats"""
        try:
            # Extract features for ML model
            features = self.threat_detector.extract_features(log_entry)
            
            # Get ML prediction
            prediction = self.threat_detector.predict(features)
            
            # Check IP against blacklist
            is_blacklisted = self._check_ip_blacklist(log_entry.get('source_ip', ''))
            
            # Check URL for phishing
            is_phishing = self._check_phishing_url(log_entry.get('details', {}).get('url', ''))
            
            # Combine all threat indicators
            threat_analysis = {
                'threat_probability': prediction.get('threat_probability', 0.0),
                'is_threat': prediction.get('is_threat', False) or is_blacklisted or is_phishing,
                'is_blacklisted_ip': is_blacklisted,
                'is_phishing_url': is_phishing,
                'threat_type': self._determine_threat_type(
                    prediction,
                    is_blacklisted,
                    is_phishing
                ),
                'feature_importances': prediction.get('feature_importances', {})
            }
            
            return threat_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing threat: {str(e)}")
            return {
                'threat_probability': 0.0,
                'is_threat': False,
                'is_blacklisted_ip': False,
                'is_phishing_url': False,
                'threat_type': 'unknown',
                'feature_importances': {},
                'error': str(e)
            }

    def log_threat(self, db: Session, log_entry: Dict[str, Any], analysis: Dict[str, Any]):
        """Log a detected threat to the database"""
        try:
            threat_log = ThreatLog(
                timestamp=datetime.now(pytz.UTC),
                source_ip=log_entry['ip'],
                destination_ip=log_entry.get('destination_ip'),
                threat_type=analysis['threat_type'],
                confidence_score=analysis['threat_probability'],
                details={
                    'url': log_entry.get('url'),
                    'method': log_entry.get('method'),
                    'status': log_entry.get('status'),
                    'analysis': analysis
                }
            )
            
            db.add(threat_log)
            db.commit()
            logger.info(f"Threat logged successfully: {analysis['threat_type']}")
            
        except Exception as e:
            logger.error(f"Error logging threat: {str(e)}")
            db.rollback()

    def send_alert(self, log_entry: Dict[str, Any], analysis: Dict[str, Any]):
        """Send an alert for a detected threat"""
        try:
            # In a real implementation, this would send alerts via email, SMS, etc.
            alert_message = (
                f"THREAT ALERT\n"
                f"Type: {analysis['threat_type']}\n"
                f"Confidence: {analysis['threat_probability']:.2%}\n"
                f"IP: {log_entry['ip']}\n"
                f"URL: {log_entry.get('url')}\n"
                f"Time: {datetime.now(pytz.UTC)}"
            )
            
            logger.warning(alert_message)
            
        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")

    def _check_ip_blacklist(self, ip: str) -> bool:
        """Check if an IP is blacklisted"""
        try:
            # In a real implementation, this would check against a database of known bad IPs
            # For now, we'll return False
            return False
        except Exception as e:
            logger.error(f"Error checking IP blacklist: {str(e)}")
            return False

    def _check_phishing_url(self, url: str) -> bool:
        """Check if a URL is potentially phishing"""
        try:
            if not self.virustotal_api_key:
                return False
                
            # In a real implementation, this would check against VirusTotal API
            # For now, we'll return False
            return False
            
        except Exception as e:
            logger.error(f"Error checking phishing URL: {str(e)}")
            return False

    def _determine_threat_type(
        self,
        prediction: Dict[str, Any],
        is_blacklisted: bool,
        is_phishing: bool
    ) -> str:
        """Determine the type of threat based on analysis results"""
        if is_phishing:
            return "phishing"
        elif is_blacklisted:
            return "blacklisted_ip"
        elif prediction['threat_probability'] > 0.95:
            return "high_confidence_threat"
        elif prediction['threat_probability'] > 0.85:
            return "suspicious_activity"
        else:
            return "unknown" 