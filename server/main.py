"""
FastAPI application entry point for FraudGuard backend.
Provides REST API endpoints for fraud detection.
"""
from fastapi import FastAPI, HTTPException, Request
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

# Middleware to log incoming requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # #region agent log
    import json; open('/Users/ayushpetwal/Desktop/FR_2/FraudGuard/.cursor/debug.log','a').write(json.dumps({'location':'main.py:36','message':'request received','data':{'method':request.method,'url':str(request.url),'path':request.url.path},'timestamp':int(__import__('time').time()*1000),'sessionId':'debug-session','runId':'run1','hypothesisId':'A,B,C,D'})+'\n')
    # #endregion
    response = await call_next(request)
    # #region agent log
    import json; open('/Users/ayushpetwal/Desktop/FR_2/FraudGuard/.cursor/debug.log','a').write(json.dumps({'location':'main.py:40','message':'response sent','data':{'statusCode':response.status_code},'timestamp':int(__import__('time').time()*1000),'sessionId':'debug-session','runId':'run1','hypothesisId':'A,B,C,D'})+'\n')
    # #endregion
    return response


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
    # #region agent log
    import json; open('/Users/ayushpetwal/Desktop/FR_2/FraudGuard/.cursor/debug.log','a').write(json.dumps({'location':'main.py:65','message':'analyze_url entry','data':{'url':str(request.url)},'timestamp':int(__import__('time').time()*1000),'sessionId':'debug-session','runId':'run1','hypothesisId':'D,E'})+'\n')
    # #endregion
    
    # Normalize URL - remove trailing slash if present for analysis
    url_str = str(request.url).rstrip('/')
    # Preserve original URL for response (without trailing slash)
    original_url = url_str
    
    try:
        # #region agent log
        import json; open('/Users/ayushpetwal/Desktop/FR_2/FraudGuard/.cursor/debug.log','a').write(json.dumps({'location':'main.py:82','message':'before analyze_url call','data':{'url':url_str},'timestamp':int(__import__('time').time()*1000),'sessionId':'debug-session','runId':'run1','hypothesisId':'E'})+'\n')
        # #endregion
        
        risk_score, signals, explanation = fraud_detector.analyze_url(url_str)
        
        # #region agent log
        import json; open('/Users/ayushpetwal/Desktop/FR_2/FraudGuard/.cursor/debug.log','a').write(json.dumps({'location':'main.py:88','message':'after analyze_url call','data':{'riskScore':risk_score,'signalsCount':len(signals)},'timestamp':int(__import__('time').time()*1000),'sessionId':'debug-session','runId':'run1','hypothesisId':'E'})+'\n')
        # #endregion
        
        risk_level = fraud_detector.get_risk_level(risk_score)
        recommendation = fraud_detector.get_recommendation(risk_level)
        
        response = AnalyzeResponse(
            url=original_url,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            signals=signals,
            explanation=explanation,
            recommendation=recommendation
        )
        
        # #region agent log
        import json; open('/Users/ayushpetwal/Desktop/FR_2/FraudGuard/.cursor/debug.log','a').write(json.dumps({'location':'main.py:105','message':'response created','data':{'riskScore':response.risk_score,'riskLevel':response.risk_level},'timestamp':int(__import__('time').time()*1000),'sessionId':'debug-session','runId':'run1','hypothesisId':'E'})+'\n')
        # #endregion
        
        return response
        
    except Exception as e:
        # #region agent log
        import json; open('/Users/ayushpetwal/Desktop/FR_2/FraudGuard/.cursor/debug.log','a').write(json.dumps({'location':'main.py:112','message':'exception in analyze_url','data':{'errorType':type(e).__name__,'errorMessage':str(e)},'timestamp':int(__import__('time').time()*1000),'sessionId':'debug-session','runId':'run1','hypothesisId':'D,E'})+'\n')
        # #endregion
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing URL: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

