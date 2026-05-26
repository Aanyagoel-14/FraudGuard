"""
FastAPI application entry point for FraudGuard backend.
Provides REST API endpoints for URL fraud detection and fraud reporting.
"""
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .models import AnalyzeRequest, AnalyzeResponse, ReportRequest, RiskLevel
from .fraud_detector import FraudDetector

# ------------------------------------------------------------------ #
#  Logging
# ------------------------------------------------------------------ #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  App setup
# ------------------------------------------------------------------ #
app = FastAPI(
    title="FraudGuard API",
    description=(
        "URL-based fraud detection service for banking and payment websites. "
        "Analyzes URLs using 6 weighted signals to produce a 0-100 risk score."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,   # Must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------ #
#  Fraud detector instance
# ------------------------------------------------------------------ #
fraud_detector = FraudDetector(
    safe_threshold=settings.safe_threshold,
    suspicious_threshold=settings.suspicious_threshold,
    safe_browsing_api_key=settings.safe_browsing_api_key,
    ssl_timeout=settings.ssl_timeout_secs,
    whois_timeout=settings.whois_timeout_secs,
)

# In-memory store for reported fraud URLs (Phase 4B)
_fraud_reports: list[dict] = []

# ------------------------------------------------------------------ #
#  Endpoints
# ------------------------------------------------------------------ #

@app.get("/")
async def root():
    """Root endpoint — service health check."""
    return {
        "service": "FraudGuard API",
        "status": "running",
        "version": "1.0.0",
        "signals": ["URL Similarity", "Domain Age", "SSL/HTTPS",
                    "Keyword Pattern", "URL Structure", "Safe Browsing"],
    }


@app.get("/health")
async def health_check():
    """Lightweight health probe for monitoring."""
    return {"status": "healthy"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest):
    """
    Analyze a URL for fraud risk.

    Returns a risk score (0-100), risk level classification (Safe/Suspicious/
    Dangerous), individual signal breakdowns, explanation, and recommendation.
    """
    # Normalize: strip trailing slash added by Pydantic's HttpUrl
    url_str = str(request.url).rstrip("/")
    logger.info("Analyzing URL: %s", url_str)

    try:
        risk_score, signals, explanation = fraud_detector.analyze_url(url_str)
        risk_level = fraud_detector.get_risk_level(risk_score)
        recommendation = fraud_detector.get_recommendation(risk_level)

        logger.info(
            "Result for %s — score=%.2f  level=%s",
            url_str, risk_score, risk_level,
        )

        return AnalyzeResponse(
            url=url_str,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            signals=signals,
            explanation=explanation,
            recommendation=recommendation,
            is_fallback=False,
        )

    except ValueError as e:
        logger.warning("Invalid URL submitted: %s — %s", url_str, e)
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error analyzing %s", url_str)
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {e}")


@app.post("/report")
async def report_fraud(request: ReportRequest):
    """
    Accept a user-submitted fraud report for a URL.

    Reports are stored in memory and logged. Future iterations can persist
    these to a database or forward to a threat-intelligence feed.
    """
    url_str = str(request.url).rstrip("/")
    report = {
        "url": url_str,
        "reason": request.reason,
        "risk_score": request.risk_score,
    }
    _fraud_reports.append(report)
    logger.warning(
        "FRAUD REPORT — url=%s  score=%s  reason=%s",
        url_str, request.risk_score, request.reason,
    )
    return {"status": "received", "message": "Thank you for helping keep the web safe."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
