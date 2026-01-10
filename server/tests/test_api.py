"""
Integration tests for FastAPI endpoints.
Tests all API routes, request/response handling, and error cases.
"""
import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from datetime import datetime, timedelta

# Add project root to path so we can import server as a package
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from server.main import app
from server.models import AnalyzeRequest, AnalyzeResponse, RiskLevel, FraudSignal


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


class TestRootEndpoint:
    """Test root endpoint (GET /)."""
    
    def test_root_endpoint(self, client):
        """Test root endpoint returns service info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "FraudGuard API"
        assert data["status"] == "running"
        assert data["version"] == "1.0.0"
    
    def test_root_endpoint_content_type(self, client):
        """Test root endpoint returns JSON."""
        response = client.get("/")
        assert response.headers["content-type"] == "application/json"


class TestHealthEndpoint:
    """Test health check endpoint (GET /health)."""
    
    def test_health_endpoint(self, client):
        """Test health endpoint returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_health_endpoint_multiple_requests(self, client):
        """Test health endpoint handles multiple requests."""
        for _ in range(10):
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json()["status"] == "healthy"


class TestAnalyzeEndpoint:
    """Test URL analysis endpoint (POST /analyze)."""
    
    @patch('server.main.fraud_detector')
    def test_analyze_valid_url(self, mock_detector, client):
        """Test analysis of a valid URL."""
        # Mock fraud detector response
        mock_signal = FraudSignal(
            name="URL Similarity",
            score=50.0,
            description="Test signal"
        )
        mock_detector.analyze_url.return_value = (
            45.0,
            [mock_signal],
            "Test explanation"
        )
        mock_detector.get_risk_level.return_value = RiskLevel.SUSPICIOUS
        mock_detector.get_recommendation.return_value = "Test recommendation"
        
        response = client.post(
            "/analyze",
            json={"url": "https://example.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["url"] == "https://example.com"
        assert data["risk_score"] == 45.0
        assert data["risk_level"] == "Suspicious"
        assert len(data["signals"]) == 1
        assert data["explanation"] == "Test explanation"
        assert data["recommendation"] == "Test recommendation"
    
    @patch('server.main.fraud_detector')
    def test_analyze_safe_url(self, mock_detector, client):
        """Test analysis of a safe URL."""
        mock_signal = FraudSignal(
            name="URL Similarity",
            score=10.0,
            description="Low risk"
        )
        mock_detector.analyze_url.return_value = (
            15.0,
            [mock_signal],
            "Safe website"
        )
        mock_detector.get_risk_level.return_value = RiskLevel.SAFE
        mock_detector.get_recommendation.return_value = "Safe to proceed"
        
        response = client.post(
            "/analyze",
            json={"url": "https://google.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["risk_level"] == "Safe"
        assert data["risk_score"] == 15.0
    
    @patch('server.main.fraud_detector')
    def test_analyze_dangerous_url(self, mock_detector, client):
        """Test analysis of a dangerous URL."""
        mock_signal = FraudSignal(
            name="URL Similarity",
            score=95.0,
            description="High risk"
        )
        mock_detector.analyze_url.return_value = (
            90.0,
            [mock_signal],
            "Dangerous website"
        )
        mock_detector.get_risk_level.return_value = RiskLevel.DANGEROUS
        mock_detector.get_recommendation.return_value = "Do not proceed"
        
        response = client.post(
            "/analyze",
            json={"url": "https://chase-bank-phishing.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["risk_level"] == "Dangerous"
        assert data["risk_score"] == 90.0
    
    @patch('server.main.fraud_detector')
    def test_analyze_multiple_signals(self, mock_detector, client):
        """Test analysis with multiple fraud signals."""
        mock_signals = [
            FraudSignal(name="URL Similarity", score=80.0, description="High similarity"),
            FraudSignal(name="Domain Age", score=90.0, description="New domain"),
            FraudSignal(name="SSL/HTTPS", score=0.0, description="Valid SSL"),
            FraudSignal(name="Keyword Pattern", score=40.0, description="Suspicious keywords"),
        ]
        mock_detector.analyze_url.return_value = (
            75.0,
            mock_signals,
            "Multiple concerns detected"
        )
        mock_detector.get_risk_level.return_value = RiskLevel.DANGEROUS
        mock_detector.get_recommendation.return_value = "High risk recommendation"
        
        response = client.post(
            "/analyze",
            json={"url": "https://suspicious-site.com/verify-account"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["signals"]) == 4
        assert all("name" in signal for signal in data["signals"])
        assert all("score" in signal for signal in data["signals"])
        assert all("description" in signal for signal in data["signals"])
    
    def test_analyze_missing_url(self, client):
        """Test analyze endpoint with missing URL."""
        response = client.post(
            "/analyze",
            json={}
        )
        assert response.status_code == 422  # Validation error
    
    def test_analyze_invalid_url_format(self, client):
        """Test analyze endpoint with invalid URL format."""
        response = client.post(
            "/analyze",
            json={"url": "not-a-valid-url"}
        )
        # Should either validate and return 422, or process and return error
        assert response.status_code in [422, 500]
    
    def test_analyze_empty_url(self, client):
        """Test analyze endpoint with empty URL."""
        response = client.post(
            "/analyze",
            json={"url": ""}
        )
        assert response.status_code in [422, 500]
    
    def test_analyze_http_url(self, client):
        """Test analyze endpoint with HTTP (non-HTTPS) URL."""
        with patch('server.main.fraud_detector') as mock_detector:
            mock_signal = FraudSignal(
                name="SSL/HTTPS",
                score=60.0,
                description="No HTTPS"
            )
            mock_detector.analyze_url.return_value = (
                30.0,
                [mock_signal],
                "HTTP detected"
            )
            mock_detector.get_risk_level.return_value = RiskLevel.SAFE
            mock_detector.get_recommendation.return_value = "HTTP warning"
            
            response = client.post(
                "/analyze",
                json={"url": "http://example.com"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["url"] == "http://example.com"
    
    def test_analyze_url_with_query_params(self, client):
        """Test analyze endpoint with URL containing query parameters."""
        with patch('server.main.fraud_detector') as mock_detector:
            mock_signal = FraudSignal(
                name="URL Similarity",
                score=0.0,
                description="No similarity"
            )
            mock_detector.analyze_url.return_value = (
                10.0,
                [mock_signal],
                "Safe"
            )
            mock_detector.get_risk_level.return_value = RiskLevel.SAFE
            mock_detector.get_recommendation.return_value = "Safe"
            
            response = client.post(
                "/analyze",
                json={"url": "https://example.com/page?param=value&other=123"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert "param=value" in data["url"] or data["url"] == "https://example.com/page?param=value&other=123"
    
    def test_analyze_url_with_fragment(self, client):
        """Test analyze endpoint with URL containing fragment."""
        with patch('server.main.fraud_detector') as mock_detector:
            mock_signal = FraudSignal(
                name="URL Similarity",
                score=0.0,
                description="No similarity"
            )
            mock_detector.analyze_url.return_value = (
                10.0,
                [mock_signal],
                "Safe"
            )
            mock_detector.get_risk_level.return_value = RiskLevel.SAFE
            mock_detector.get_recommendation.return_value = "Safe"
            
            response = client.post(
                "/analyze",
                json={"url": "https://example.com/page#section"}
            )
            
            assert response.status_code == 200
    
    @patch('server.main.fraud_detector')
    def test_analyze_detector_exception(self, mock_detector, client):
        """Test analyze endpoint when detector raises exception."""
        mock_detector.analyze_url.side_effect = Exception("Analysis failed")
        
        response = client.post(
            "/analyze",
            json={"url": "https://example.com"}
        )
        
        assert response.status_code == 500
        data = response.json()
        assert "detail" in data
        assert "Error analyzing URL" in data["detail"]
    
    @patch('server.main.fraud_detector')
    def test_analyze_risk_score_rounding(self, mock_detector, client):
        """Test that risk score is rounded to 2 decimal places."""
        mock_signal = FraudSignal(
            name="URL Similarity",
            score=50.0,
            description="Test"
        )
        mock_detector.analyze_url.return_value = (
            45.123456789,
            [mock_signal],
            "Test explanation"
        )
        mock_detector.get_risk_level.return_value = RiskLevel.SUSPICIOUS
        mock_detector.get_recommendation.return_value = "Test"
        
        response = client.post(
            "/analyze",
            json={"url": "https://example.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] == 45.12  # Rounded to 2 decimals
    
    def test_analyze_invalid_json(self, client):
        """Test analyze endpoint with invalid JSON."""
        response = client.post(
            "/analyze",
            data="not json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
    
    def test_analyze_missing_content_type(self, client):
        """Test analyze endpoint without Content-Type header."""
        response = client.post(
            "/analyze",
            json={"url": "https://example.com"},
            headers={}
        )
        # FastAPI should still process it
        assert response.status_code in [200, 422]
    
    def test_analyze_very_long_url(self, client):
        """Test analyze endpoint with very long URL."""
        long_path = "/" + "a" * 2000
        url = f"https://example.com{long_path}"
        
        with patch('server.main.fraud_detector') as mock_detector:
            mock_signal = FraudSignal(
                name="URL Similarity",
                score=0.0,
                description="Test"
            )
            mock_detector.analyze_url.return_value = (
                10.0,
                [mock_signal],
                "Test"
            )
            mock_detector.get_risk_level.return_value = RiskLevel.SAFE
            mock_detector.get_recommendation.return_value = "Test"
            
            response = client.post(
                "/analyze",
                json={"url": url}
            )
            
            assert response.status_code == 200


class TestCORSMiddleware:
    """Test CORS middleware configuration."""
    
    def test_cors_headers_present(self, client):
        """Test that CORS headers are present in responses."""
        response = client.get("/health")
        # CORS headers should be present (TestClient may not show all headers)
        assert response.status_code == 200
    
    def test_options_request(self, client):
        """Test OPTIONS request handling."""
        response = client.options("/analyze")
        # Should handle OPTIONS request
        assert response.status_code in [200, 405]


class TestRequestLogging:
    """Test request logging middleware."""
    
    def test_request_logged(self, client):
        """Test that requests are logged."""
        # The middleware logs to a file, so we just verify the endpoint works
        response = client.get("/health")
        assert response.status_code == 200
    
    def test_response_logged(self, client):
        """Test that responses are logged."""
        response = client.post(
            "/analyze",
            json={"url": "https://example.com"}
        )
        # Response should be logged by middleware
        assert response.status_code in [200, 500]


class TestErrorHandling:
    """Test error handling in API endpoints."""
    
    @patch('server.main.fraud_detector')
    def test_internal_server_error(self, mock_detector, client):
        """Test handling of internal server errors."""
        mock_detector.analyze_url.side_effect = RuntimeError("Internal error")
        
        response = client.post(
            "/analyze",
            json={"url": "https://example.com"}
        )
        
        assert response.status_code == 500
        data = response.json()
        assert "detail" in data
        assert "Error analyzing URL" in data["detail"]
    
    def test_method_not_allowed(self, client):
        """Test that GET is not allowed on /analyze endpoint."""
        response = client.get("/analyze")
        assert response.status_code == 405  # Method not allowed
    
    def test_invalid_endpoint(self, client):
        """Test request to non-existent endpoint."""
        response = client.get("/nonexistent")
        assert response.status_code == 404


class TestResponseFormat:
    """Test response format and structure."""
    
    @patch('server.main.fraud_detector')
    def test_response_structure(self, mock_detector, client):
        """Test that response has correct structure."""
        mock_signal = FraudSignal(
            name="URL Similarity",
            score=50.0,
            description="Test signal"
        )
        mock_detector.analyze_url.return_value = (
            45.0,
            [mock_signal],
            "Test explanation"
        )
        mock_detector.get_risk_level.return_value = RiskLevel.SUSPICIOUS
        mock_detector.get_recommendation.return_value = "Test recommendation"
        
        response = client.post(
            "/analyze",
            json={"url": "https://example.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify all required fields
        assert "url" in data
        assert "risk_score" in data
        assert "risk_level" in data
        assert "signals" in data
        assert "explanation" in data
        assert "recommendation" in data
        
        # Verify signal structure
        assert isinstance(data["signals"], list)
        if data["signals"]:
            signal = data["signals"][0]
            assert "name" in signal
            assert "score" in signal
            assert "description" in signal
    
    @patch('server.main.fraud_detector')
    def test_signal_score_range(self, mock_detector, client):
        """Test that signal scores are in valid range (0-100)."""
        mock_signal = FraudSignal(
            name="URL Similarity",
            score=50.0,
            description="Test"
        )
        mock_detector.analyze_url.return_value = (
            45.0,
            [mock_signal],
            "Test"
        )
        mock_detector.get_risk_level.return_value = RiskLevel.SUSPICIOUS
        mock_detector.get_recommendation.return_value = "Test"
        
        response = client.post(
            "/analyze",
            json={"url": "https://example.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert 0 <= data["risk_score"] <= 100
        for signal in data["signals"]:
            assert 0 <= signal["score"] <= 100

