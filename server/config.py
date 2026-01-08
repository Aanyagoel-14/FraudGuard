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
    
    # Azure OpenAI configuration (optional)
    azure_openai_endpoint: Optional[str] = None
    azure_openai_key: Optional[str] = None
    azure_openai_deployment: Optional[str] = None
    azure_openai_api_version: str = "2023-12-01-preview"
    
    # Fraud detection thresholds
    safe_threshold: int = 30
    suspicious_threshold: int = 70
    dangerous_threshold: int = 100
    
    # CORS configuration - Allow all origins for Chrome extensions
    cors_origins: list[str] = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()

