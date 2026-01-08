"""
FastAPI application entry point for FraudGuard backend.
Provides REST API endpoints for fraud detection.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .models import AnalyzeRequest, AnalyzeResponse, RiskLevel
from .fraud_detector import FraudDetector

# Initialize FastAPI app
app = FastAPI(
    title="FraudGuard API",
    description="AI-powered fraud detection service for bank and payment websites",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize fraud detector with configurable thresholds
fraud_detector = FraudDetector(
    safe_threshold=settings.safe_threshold,
    suspicious_threshold=settings.suspicious_threshold,
)


@app.get("/")
async def root():
    """Root endpoint - health check."""
    return {
        "service": "FraudGuard API",
        "status": "running",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest):
    """
    Analyze a URL for fraud risk.
    
    Args:
        request: AnalyzeRequest containing the URL to analyze
        
    Returns:
        AnalyzeResponse with risk score, level, signals, and recommendations
    """
    url = str(request.url)
    
    try:
        risk_score, signals, explanation = fraud_detector.analyze_url(url)
        risk_level = fraud_detector.get_risk_level(risk_score)
        recommendation = fraud_detector.get_recommendation(risk_level)
        
        response = AnalyzeResponse(
            url=url,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            signals=signals,
            explanation=explanation,
            recommendation=recommendation
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing URL: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

