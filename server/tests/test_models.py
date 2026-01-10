"""
Unit tests for Pydantic models.
Tests data validation, serialization, and model behavior.
"""
import pytest
import sys
from pathlib import Path
from pydantic import ValidationError

# Add project root to path so we can import server as a package
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from server.models import (
    RiskLevel,
    AnalyzeRequest,
    AnalyzeResponse,
    FraudSignal
)


class TestRiskLevel:
    """Test RiskLevel enum."""
    
    def test_risk_level_values(self):
        """Test that RiskLevel has correct values."""
        assert RiskLevel.SAFE == "Safe"
        assert RiskLevel.SUSPICIOUS == "Suspicious"
        assert RiskLevel.DANGEROUS == "Dangerous"
    
    def test_risk_level_enum_membership(self):
        """Test RiskLevel enum membership."""
        assert isinstance(RiskLevel.SAFE, RiskLevel)
        assert RiskLevel.SAFE in RiskLevel
    
    def test_risk_level_string_representation(self):
        """Test RiskLevel string representation."""
        assert str(RiskLevel.SAFE) == "Safe"
        assert str(RiskLevel.SUSPICIOUS) == "Suspicious"
        assert str(RiskLevel.DANGEROUS) == "Dangerous"


class TestFraudSignal:
    """Test FraudSignal model."""
    
    def test_fraud_signal_creation(self):
        """Test creating a valid FraudSignal."""
        signal = FraudSignal(
            name="URL Similarity",
            score=50.0,
            description="Test signal"
        )
        assert signal.name == "URL Similarity"
        assert signal.score == 50.0
        assert signal.description == "Test signal"
    
    def test_fraud_signal_score_min(self):
        """Test FraudSignal with minimum score (0)."""
        signal = FraudSignal(
            name="Test",
            score=0.0,
            description="Test"
        )
        assert signal.score == 0.0
    
    def test_fraud_signal_score_max(self):
        """Test FraudSignal with maximum score (100)."""
        signal = FraudSignal(
            name="Test",
            score=100.0,
            description="Test"
        )
        assert signal.score == 100.0
    
    def test_fraud_signal_score_below_min(self):
        """Test FraudSignal validation with score below 0."""
        with pytest.raises(ValidationError):
            FraudSignal(
                name="Test",
                score=-10.0,
                description="Test"
            )
    
    def test_fraud_signal_score_above_max(self):
        """Test FraudSignal validation with score above 100."""
        with pytest.raises(ValidationError):
            FraudSignal(
                name="Test",
                score=150.0,
                description="Test"
            )
    
    def test_fraud_signal_missing_fields(self):
        """Test FraudSignal validation with missing fields."""
        with pytest.raises(ValidationError):
            FraudSignal(name="Test")
    
    def test_fraud_signal_empty_name(self):
        """Test FraudSignal with empty name."""
        signal = FraudSignal(
            name="",
            score=50.0,
            description="Test"
        )
        assert signal.name == ""
    
    def test_fraud_signal_empty_description(self):
        """Test FraudSignal with empty description."""
        signal = FraudSignal(
            name="Test",
            score=50.0,
            description=""
        )
        assert signal.description == ""
    
    def test_fraud_signal_float_score(self):
        """Test FraudSignal with float score."""
        signal = FraudSignal(
            name="Test",
            score=45.5,
            description="Test"
        )
        assert signal.score == 45.5
    
    def test_fraud_signal_int_score(self):
        """Test FraudSignal with integer score (should convert to float)."""
        signal = FraudSignal(
            name="Test",
            score=50,
            description="Test"
        )
        assert isinstance(signal.score, (int, float))
        assert signal.score == 50


class TestAnalyzeRequest:
    """Test AnalyzeRequest model."""
    
    def test_analyze_request_creation(self):
        """Test creating a valid AnalyzeRequest."""
        request = AnalyzeRequest(url="https://example.com")
        assert str(request.url) == "https://example.com/"
    
    def test_analyze_request_http_url(self):
        """Test AnalyzeRequest with HTTP URL."""
        request = AnalyzeRequest(url="http://example.com")
        assert "http://" in str(request.url)
    
    def test_analyze_request_https_url(self):
        """Test AnalyzeRequest with HTTPS URL."""
        request = AnalyzeRequest(url="https://example.com")
        assert "https://" in str(request.url)
    
    def test_analyze_request_url_with_path(self):
        """Test AnalyzeRequest with URL containing path."""
        request = AnalyzeRequest(url="https://example.com/page")
        assert "example.com" in str(request.url)
    
    def test_analyze_request_url_with_query(self):
        """Test AnalyzeRequest with URL containing query parameters."""
        request = AnalyzeRequest(url="https://example.com?param=value")
        assert "example.com" in str(request.url)
    
    def test_analyze_request_invalid_url(self):
        """Test AnalyzeRequest validation with invalid URL."""
        with pytest.raises(ValidationError):
            AnalyzeRequest(url="not-a-url")
    
    def test_analyze_request_empty_url(self):
        """Test AnalyzeRequest validation with empty URL."""
        with pytest.raises(ValidationError):
            AnalyzeRequest(url="")
    
    def test_analyze_request_missing_url(self):
        """Test AnalyzeRequest validation with missing URL."""
        with pytest.raises(ValidationError):
            AnalyzeRequest()
    
    def test_analyze_request_url_serialization(self):
        """Test AnalyzeRequest URL serialization."""
        request = AnalyzeRequest(url="https://example.com")
        # Should be able to convert to dict/JSON
        data = request.model_dump()
        assert "url" in data


class TestAnalyzeResponse:
    """Test AnalyzeResponse model."""
    
    def test_analyze_response_creation(self):
        """Test creating a valid AnalyzeResponse."""
        signals = [
            FraudSignal(name="Test", score=50.0, description="Test signal")
        ]
        response = AnalyzeResponse(
            url="https://example.com",
            risk_score=45.0,
            risk_level=RiskLevel.SUSPICIOUS,
            signals=signals,
            explanation="Test explanation",
            recommendation="Test recommendation"
        )
        assert response.url == "https://example.com"
        assert response.risk_score == 45.0
        assert response.risk_level == RiskLevel.SUSPICIOUS
        assert len(response.signals) == 1
        assert response.explanation == "Test explanation"
        assert response.recommendation == "Test recommendation"
    
    def test_analyze_response_min_risk_score(self):
        """Test AnalyzeResponse with minimum risk score."""
        response = AnalyzeResponse(
            url="https://example.com",
            risk_score=0.0,
            risk_level=RiskLevel.SAFE,
            signals=[],
            explanation="Safe",
            recommendation="Proceed"
        )
        assert response.risk_score == 0.0
    
    def test_analyze_response_max_risk_score(self):
        """Test AnalyzeResponse with maximum risk score."""
        response = AnalyzeResponse(
            url="https://example.com",
            risk_score=100.0,
            risk_level=RiskLevel.DANGEROUS,
            signals=[],
            explanation="Dangerous",
            recommendation="Do not proceed"
        )
        assert response.risk_score == 100.0
    
    def test_analyze_response_risk_score_below_min(self):
        """Test AnalyzeResponse validation with risk score below 0."""
        with pytest.raises(ValidationError):
            AnalyzeResponse(
                url="https://example.com",
                risk_score=-10.0,
                risk_level=RiskLevel.SAFE,
                signals=[],
                explanation="Test",
                recommendation="Test"
            )
    
    def test_analyze_response_risk_score_above_max(self):
        """Test AnalyzeResponse validation with risk score above 100."""
        with pytest.raises(ValidationError):
            AnalyzeResponse(
                url="https://example.com",
                risk_score=150.0,
                risk_level=RiskLevel.SAFE,
                signals=[],
                explanation="Test",
                recommendation="Test"
            )
    
    def test_analyze_response_empty_signals(self):
        """Test AnalyzeResponse with empty signals list."""
        response = AnalyzeResponse(
            url="https://example.com",
            risk_score=50.0,
            risk_level=RiskLevel.SUSPICIOUS,
            signals=[],
            explanation="Test",
            recommendation="Test"
        )
        assert len(response.signals) == 0
    
    def test_analyze_response_multiple_signals(self):
        """Test AnalyzeResponse with multiple signals."""
        signals = [
            FraudSignal(name="Signal 1", score=50.0, description="Test 1"),
            FraudSignal(name="Signal 2", score=60.0, description="Test 2"),
        ]
        response = AnalyzeResponse(
            url="https://example.com",
            risk_score=55.0,
            risk_level=RiskLevel.SUSPICIOUS,
            signals=signals,
            explanation="Test",
            recommendation="Test"
        )
        assert len(response.signals) == 2
    
    def test_analyze_response_all_risk_levels(self):
        """Test AnalyzeResponse with all risk levels."""
        for risk_level in [RiskLevel.SAFE, RiskLevel.SUSPICIOUS, RiskLevel.DANGEROUS]:
            response = AnalyzeResponse(
                url="https://example.com",
                risk_score=50.0,
                risk_level=risk_level,
                signals=[],
                explanation="Test",
                recommendation="Test"
            )
            assert response.risk_level == risk_level
    
    def test_analyze_response_missing_fields(self):
        """Test AnalyzeResponse validation with missing fields."""
        with pytest.raises(ValidationError):
            AnalyzeResponse(
                url="https://example.com",
                risk_score=50.0,
                risk_level=RiskLevel.SUSPICIOUS
                # Missing signals, explanation, recommendation
            )
    
    def test_analyze_response_serialization(self):
        """Test AnalyzeResponse serialization to dict/JSON."""
        signals = [
            FraudSignal(name="Test", score=50.0, description="Test")
        ]
        response = AnalyzeResponse(
            url="https://example.com",
            risk_score=45.0,
            risk_level=RiskLevel.SUSPICIOUS,
            signals=signals,
            explanation="Test",
            recommendation="Test"
        )
        data = response.model_dump()
        assert "url" in data
        assert "risk_score" in data
        assert "risk_level" in data
        assert "signals" in data
        assert "explanation" in data
        assert "recommendation" in data
    
    def test_analyze_response_json_serialization(self):
        """Test AnalyzeResponse JSON serialization."""
        signals = [
            FraudSignal(name="Test", score=50.0, description="Test")
        ]
        response = AnalyzeResponse(
            url="https://example.com",
            risk_score=45.0,
            risk_level=RiskLevel.SUSPICIOUS,
            signals=signals,
            explanation="Test",
            recommendation="Test"
        )
        json_str = response.model_dump_json()
        assert isinstance(json_str, str)
        assert "example.com" in json_str


class TestModelIntegration:
    """Test integration between models."""
    
    def test_request_response_flow(self):
        """Test complete request-response flow with models."""
        # Create request
        request = AnalyzeRequest(url="https://example.com")
        assert request.url is not None
        
        # Create response
        signals = [
            FraudSignal(name="URL Similarity", score=50.0, description="Test")
        ]
        response = AnalyzeResponse(
            url=str(request.url),
            risk_score=45.0,
            risk_level=RiskLevel.SUSPICIOUS,
            signals=signals,
            explanation="Test explanation",
            recommendation="Test recommendation"
        )
        
        # Verify response structure
        assert response.url is not None
        assert response.risk_score >= 0
        assert response.risk_level in RiskLevel
        assert len(response.signals) > 0
    
    def test_signal_in_response(self):
        """Test that FraudSignal can be included in AnalyzeResponse."""
        signal = FraudSignal(
            name="Test Signal",
            score=75.0,
            description="Test description"
        )
        response = AnalyzeResponse(
            url="https://example.com",
            risk_score=75.0,
            risk_level=RiskLevel.DANGEROUS,
            signals=[signal],
            explanation="Test",
            recommendation="Test"
        )
        assert response.signals[0].name == "Test Signal"
        assert response.signals[0].score == 75.0

