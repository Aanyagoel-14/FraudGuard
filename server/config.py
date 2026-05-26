"""
Configuration management for FraudGuard backend.
Handles environment variables and application settings.
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Backend configuration
    backend_url: str = "http://localhost:8000"

    # Fraud detection thresholds
    safe_threshold: int = 30
    suspicious_threshold: int = 70
    dangerous_threshold: int = 100

    # External lookup timeouts (seconds)
    whois_timeout_secs: int = 5
    ssl_timeout_secs: int = 5

    # Google Safe Browsing API (optional — signals skipped gracefully if not set)
    safe_browsing_api_key: Optional[str] = None

    # CORS configuration — allow all origins for Chrome extensions
    cors_origins: list[str] = ["*"]

    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
