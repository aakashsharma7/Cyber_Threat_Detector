from typing import List
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, Field
import secrets

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = secrets.token_urlsafe(32)
    # JWT token expiration time (8 days)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 11520  # 8 days in minutes
    
    # CORS Configuration - Hardcoded values
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8501"]
    
    # Security
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    
    # Database
    DATABASE_URL: str = "postgresql://threat_detector_owner:npg_59nQaNTCWUlc@ep-super-band-a8kqct5c-pooler.eastus2.azure.neon.tech/threat_detector?sslmode=require"
    
    # VirusTotal API
    VIRUSTOTAL_API_KEY: str = "91a31bfcd274e1c692f3ca819f2d0421422a745c9921bdf62bd1d2a64998ebcf"
    
    # GeoIP Database
    GEOIP_DATABASE_PATH: str = "GeoLite2-City.mmdb"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # ML Model Settings
    MODEL_PATH: str = "app/ml/models/threat_detector.pkl"
    CONFIDENCE_THRESHOLD: float = 0.85
    
    # Scheduler Settings
    SCAN_INTERVAL_MINUTES: int = 5
    
    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        case_sensitive = True
        # Exclude ALLOWED_ORIGINS from environment variable parsing
        env_prefix = ""
        extra = "ignore"

settings = Settings()
