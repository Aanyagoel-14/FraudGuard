"""
Pydantic models for request and response schemas.
"""
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional
from enum import Enum


class RiskLevel(str, Enum):
    """Risk classification levels."""
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    DANGEROUS = "Dangerous"

    def __str__(self) -> str:
        """Return the string value of the enum."""
        return self.value


class AnalyzeRequest(BaseModel):
    """Request model for URL analysis endpoint."""
    url: HttpUrl = Field(..., description="The URL to analyze for fraud risk")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example-bank.com/login"
            }
        }


class FraudSignal(BaseModel):
    """Individual fraud detection signal."""
    name: str = Field(..., description="Name of the fraud signal")
    score: float = Field(..., ge=0, le=100, description="Signal score (0-100)")
    description: str = Field(..., description="Human-readable description of the signal")


class ReportRequest(BaseModel):
    """Request model for fraud reporting endpoint."""
    url: HttpUrl = Field(..., description="The URL being reported as fraudulent")
    reason: Optional[str] = Field(None, description="Optional reason for the report")
    risk_score: Optional[float] = Field(None, ge=0, le=100, description="Risk score at time of report")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://fake-bank-login.tk/verify",
                "reason": "Phishing site impersonating my bank",
                "risk_score": 85.0
            }
        }


class AnalyzeResponse(BaseModel):
    """Response model for URL analysis endpoint."""
    url: str = Field(..., description="The analyzed URL")
    risk_score: float = Field(..., ge=0, le=100, description="Overall fraud risk score (0-100)")
    risk_level: RiskLevel = Field(..., description="Risk classification level")
    signals: List[FraudSignal] = Field(..., description="List of fraud detection signals")
    explanation: str = Field(..., description="Human-readable explanation of the risk assessment")
    recommendation: str = Field(..., description="Recommended action for the user")
    is_fallback: bool = Field(False, description="True if this result is a degraded-mode fallback due to backend failure")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example-bank.com/login",
                "risk_score": 75.5,
                "risk_level": "Dangerous",
                "signals": [
                    {
                        "name": "URL Similarity",
                        "score": 85.0,
                        "description": "High similarity to known bank domain"
                    }
                ],
                "explanation": "This website shows high similarity to a known legitimate bank domain.",
                "recommendation": "Do not enter any personal or financial information. Exit this site immediately.",
                "is_fallback": False
            }
        }
