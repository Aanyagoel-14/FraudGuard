"""
Comprehensive unit tests for FraudDetector class.
Tests all fraud detection algorithms and edge cases.
"""
import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Add project root to path so we can import server as a package
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from server.fraud_detector import FraudDetector
from server.models import FraudSignal, RiskLevel


class TestFraudDetectorInitialization:
    """Test FraudDetector initialization."""
    
    def test_init_with_default_thresholds(self):
        """Test initialization with custom thresholds."""
        detector = FraudDetector(safe_threshold=30, suspicious_threshold=70)
        assert detector.safe_threshold == 30
        assert detector.suspicious_threshold == 70
    
    def test_init_with_custom_thresholds(self):
        """Test initialization with different threshold values."""
        detector = FraudDetector(safe_threshold=20, suspicious_threshold=80)
        assert detector.safe_threshold == 20
        assert detector.suspicious_threshold == 80
    
    def test_init_thresholds_validation(self):
        """Test that thresholds can be set to any integer value."""
        detector = FraudDetector(safe_threshold=0, suspicious_threshold=100)
        assert detector.safe_threshold == 0
        assert detector.suspicious_threshold == 100


class TestDomainNormalization:
    """Test domain normalization functionality."""
    
    def test_normalize_domain_removes_www(self, fraud_detector):
        """Test that www prefix is removed."""
        domain = fraud_detector._normalize_domain("www.example.com")
        assert domain == "example.com"
    
    def test_normalize_domain_removes_port(self, fraud_detector):
        """Test that port numbers are removed."""
        domain = fraud_detector._normalize_domain("example.com:8080")
        assert domain == "example.com"
    
    def test_normalize_domain_lowercase(self, fraud_detector):
        """Test that domain is converted to lowercase."""
        domain = fraud_detector._normalize_domain("EXAMPLE.COM")
        assert domain == "example.com"
    
    def test_normalize_domain_www_and_port(self, fraud_detector):
        """Test normalization with both www and port."""
        domain = fraud_detector._normalize_domain("www.example.com:443")
        assert domain == "example.com"
    
    def test_normalize_domain_no_changes_needed(self, fraud_detector):
        """Test domain that doesn't need normalization."""
        domain = fraud_detector._normalize_domain("example.com")
        assert domain == "example.com"
    
    def test_normalize_domain_subdomain(self, fraud_detector):
        """Test that subdomains are preserved."""
        domain = fraud_detector._normalize_domain("subdomain.example.com")
        assert domain == "subdomain.example.com"


class TestURLSimilarity:
    """Test URL similarity detection."""
    
    def test_high_similarity_typosquatting(self, fraud_detector):
        """Test detection of typosquatting (high similarity)."""
        signal = fraud_detector._check_url_similarity("chase-bank.com")
        assert signal.name == "URL Similarity"
        assert signal.score > 70  # High similarity threshold
        assert "chase" in signal.description.lower()
    
    def test_high_similarity_character_substitution(self, fraud_detector):
        """Test detection of character substitution (e.g., paypa1.com)."""
        signal = fraud_detector._check_url_similarity("paypa1.com")
        assert signal.score > 70
        assert "paypal" in signal.description.lower()
    
    def test_moderate_similarity(self, fraud_detector):
        """Test moderate similarity detection."""
        signal = fraud_detector._check_url_similarity("banking-service.com")
        assert signal.name == "URL Similarity"
        assert 0 < signal.score <= 50  # Moderate similarity
    
    def test_no_similarity(self, fraud_detector):
        """Test domain with no similarity to legitimate domains."""
        signal = fraud_detector._check_url_similarity("example.com")
        assert signal.name == "URL Similarity"
        assert signal.score == 0
        assert "does not match" in signal.description.lower()
    
    def test_exact_match_legitimate_domain(self, fraud_detector):
        """Test that exact match to legitimate domain has low score."""
        signal = fraud_detector._check_url_similarity("chase.com")
        # Exact match should not trigger similarity warning
        assert signal.score == 0 or signal.score < 50
    
    def test_similarity_with_all_legitimate_domains(self, fraud_detector):
        """Test similarity check against all legitimate domains."""
        for domain in fraud_detector.LEGITIMATE_DOMAINS:
            # Create a typosquatting variant
            typosquat = domain.replace(".com", "-secure.com")
            signal = fraud_detector._check_url_similarity(typosquat)
            assert signal.name == "URL Similarity"
            assert isinstance(signal.score, (int, float))
            assert 0 <= signal.score <= 100


class TestDomainAge:
    """Test domain age checking using WHOIS."""
    
    @patch('server.fraud_detector.whois.whois')
    def test_new_domain_high_risk(self, mock_whois, fraud_detector):
        """Test that new domains (< 30 days) get high risk score."""
        mock_record = Mock()
        mock_record.creation_date = datetime.now() - timedelta(days=15)
        mock_whois.return_value = mock_record
        
        signal = fraud_detector._check_domain_age("newdomain.com")
        assert signal.name == "Domain Age"
        assert signal.score == 90.0
        # Allow for off-by-one day due to time calculation
        assert "14 days" in signal.description or "15 days" in signal.description
    
    @patch('server.fraud_detector.whois.whois')
    def test_recent_domain_medium_risk(self, mock_whois, fraud_detector):
        """Test that recent domains (30-180 days) get medium risk score."""
        mock_record = Mock()
        mock_record.creation_date = datetime.now() - timedelta(days=100)
        mock_whois.return_value = mock_record
        
        signal = fraud_detector._check_domain_age("recentdomain.com")
        assert signal.name == "Domain Age"
        assert signal.score == 60.0
        # Allow for off-by-one day due to time calculation
        assert "99 days" in signal.description or "100 days" in signal.description
    
    @patch('server.fraud_detector.whois.whois')
    def test_old_domain_low_risk(self, mock_whois, fraud_detector):
        """Test that old domains (> 180 days) get low risk score."""
        mock_record = Mock()
        mock_record.creation_date = datetime.now() - timedelta(days=365)
        mock_whois.return_value = mock_record
        
        signal = fraud_detector._check_domain_age("olddomain.com")
        assert signal.name == "Domain Age"
        assert signal.score == 0.0
        assert "seasoned" in signal.description.lower()
    
    @patch('server.fraud_detector.whois.whois')
    def test_whois_failure_handling(self, mock_whois, fraud_detector):
        """Test handling of WHOIS lookup failures."""
        mock_whois.side_effect = Exception("WHOIS lookup failed")
        
        signal = fraud_detector._check_domain_age("testdomain.com")
        assert signal.name == "Domain Age"
        assert signal.score == 90.0  # Treated as neutral/risky
        assert "Could not verify" in signal.description
    
    @patch('server.fraud_detector.whois.whois')
    def test_whois_missing_creation_date(self, mock_whois, fraud_detector):
        """Test handling of missing creation date in WHOIS record."""
        mock_record = Mock()
        mock_record.creation_date = None
        mock_whois.return_value = mock_record
        
        signal = fraud_detector._check_domain_age("testdomain.com")
        assert signal.name == "Domain Age"
        assert signal.score == 90.0
        assert "Could not verify" in signal.description
    
    @patch('server.fraud_detector.whois.whois')
    def test_whois_list_creation_date(self, mock_whois, fraud_detector):
        """Test handling of list creation date in WHOIS record."""
        mock_record = Mock()
        mock_record.creation_date = [datetime.now() - timedelta(days=50)]
        mock_whois.return_value = mock_record
        
        signal = fraud_detector._check_domain_age("testdomain.com")
        assert signal.name == "Domain Age"
        assert signal.score == 60.0
    
    @patch('server.fraud_detector.whois.whois')
    def test_whois_string_creation_date(self, mock_whois, fraud_detector):
        """Test handling of string creation date in WHOIS record."""
        mock_record = Mock()
        mock_record.creation_date = (datetime.now() - timedelta(days=50)).strftime("%Y-%m-%d")
        mock_whois.return_value = mock_record
        
        signal = fraud_detector._check_domain_age("testdomain.com")
        assert signal.name == "Domain Age"
        assert isinstance(signal.score, (int, float))


class TestSSLCheck:
    """Test SSL/HTTPS certificate validation."""
    
    def test_http_url_no_https(self, fraud_detector):
        """Test that HTTP URLs (without HTTPS) get flagged."""
        signal = fraud_detector._check_ssl("example.com", "http://example.com")
        assert signal.name == "SSL/HTTPS"
        assert signal.score == 60.0
        assert "does not use HTTPS" in signal.description
    
    def test_https_url_with_valid_cert(self, fraud_detector):
        """Test HTTPS URL with valid certificate."""
        with patch('server.fraud_detector.socket.create_connection') as mock_conn, \
             patch('server.fraud_detector.ssl.create_default_context') as mock_ssl_ctx:
            
            # Mock SSL socket
            mock_ssl_sock = Mock()
            expiry_date = datetime.utcnow() + timedelta(days=90)
            mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
            mock_ssl_sock.getpeercert.return_value = mock_cert
            
            # Mock context wrap_socket
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            mock_ssl_ctx.return_value = mock_context
            
            # Mock socket connection
            mock_sock = Mock()
            mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = Mock(return_value=False)
            
            signal = fraud_detector._check_ssl("example.com", "https://example.com")
            assert signal.name == "SSL/HTTPS"
            assert signal.score == 90.0  # Valid certificate
            assert "Valid SSL certificate" in signal.description
    
    def test_https_url_with_expired_cert(self, fraud_detector):
        """Test HTTPS URL with expired certificate."""
        with patch('server.fraud_detector.socket.create_connection') as mock_conn, \
             patch('server.fraud_detector.ssl.create_default_context') as mock_ssl_ctx:
            
            mock_ssl_sock = Mock()
            expiry_date = datetime.utcnow() - timedelta(days=10)
            mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
            mock_ssl_sock.getpeercert.return_value = mock_cert
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            mock_ssl_ctx.return_value = mock_context
            
            mock_sock = Mock()
            mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = Mock(return_value=False)
            
            signal = fraud_detector._check_ssl("example.com", "https://example.com")
            assert signal.name == "SSL/HTTPS"
            assert signal.score == 90.0
            assert "expired" in signal.description.lower()
    
    def test_https_url_cert_expiring_soon(self, fraud_detector):
        """Test HTTPS URL with certificate expiring soon."""
        with patch('server.fraud_detector.socket.create_connection') as mock_conn, \
             patch('server.fraud_detector.ssl.create_default_context') as mock_ssl_ctx:
            
            mock_ssl_sock = Mock()
            expiry_date = datetime.utcnow() + timedelta(days=15)
            mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
            mock_ssl_sock.getpeercert.return_value = mock_cert
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            mock_ssl_ctx.return_value = mock_context
            
            mock_sock = Mock()
            mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = Mock(return_value=False)
            
            signal = fraud_detector._check_ssl("example.com", "https://example.com")
            assert signal.name == "SSL/HTTPS"
            assert signal.score == 50.0
            assert "expires soon" in signal.description.lower()
    
    def test_ssl_check_network_failure(self, fraud_detector):
        """Test handling of network failures during SSL check."""
        with patch('server.fraud_detector.socket.create_connection') as mock_conn:
            mock_conn.side_effect = Exception("Network error")
            
            signal = fraud_detector._check_ssl("example.com", "https://example.com")
            assert signal.name == "SSL/HTTPS"
            assert signal.score == 0.0  # Treated as neutral
            assert "Could not validate" in signal.description
    
    def test_ssl_check_missing_cert_expiry(self, fraud_detector):
        """Test handling of certificate missing expiry date."""
        with patch('server.fraud_detector.socket.create_connection') as mock_conn, \
             patch('server.fraud_detector.ssl.create_default_context') as mock_ssl_ctx:
            
            mock_ssl_sock = Mock()
            mock_ssl_sock.getpeercert.return_value = {}  # Missing notAfter
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            mock_ssl_ctx.return_value = mock_context
            
            mock_sock = Mock()
            mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = Mock(return_value=False)
            
            signal = fraud_detector._check_ssl("example.com", "https://example.com")
            assert signal.name == "SSL/HTTPS"
            assert signal.score == 0.0
            assert "Could not validate" in signal.description


class TestKeywordDetection:
    """Test phishing keyword pattern detection."""
    
    def test_no_keywords_found(self, fraud_detector):
        """Test URL with no suspicious keywords."""
        signal = fraud_detector._check_keywords("https://example.com/page")
        assert signal.name == "Keyword Pattern"
        assert signal.score == 0
        assert "No suspicious keywords" in signal.description
    
    def test_single_keyword_found(self, fraud_detector):
        """Test URL with one suspicious keyword."""
        signal = fraud_detector._check_keywords("https://example.com/secure-login")
        assert signal.name == "Keyword Pattern"
        assert signal.score == 20
        assert "secure-login" in signal.description
    
    def test_multiple_keywords_found(self, fraud_detector):
        """Test URL with multiple suspicious keywords."""
        signal = fraud_detector._check_keywords(
            "https://example.com/verify-account/update-info"
        )
        assert signal.name == "Keyword Pattern"
        assert signal.score >= 40  # Multiple keywords
        assert "verify-account" in signal.description or "update-info" in signal.description
    
    def test_all_keywords_detected(self, fraud_detector):
        """Test that all phishing keywords are detected."""
        for keyword in fraud_detector.PHISHING_KEYWORDS:
            url = f"https://example.com/{keyword}"
            signal = fraud_detector._check_keywords(url)
            assert signal.name == "Keyword Pattern"
            assert signal.score > 0
            assert keyword in signal.description
    
    def test_keyword_case_insensitive(self, fraud_detector):
        """Test that keyword detection is case insensitive."""
        signal = fraud_detector._check_keywords("https://example.com/SECURE-LOGIN")
        assert signal.name == "Keyword Pattern"
        assert signal.score > 0
    
    def test_keyword_in_path(self, fraud_detector):
        """Test keyword detection in URL path."""
        signal = fraud_detector._check_keywords("https://example.com/path/verify-now/page")
        assert signal.name == "Keyword Pattern"
        assert signal.score > 0


class TestRiskScoreCalculation:
    """Test risk score calculation from signals."""
    
    def test_empty_signals_list(self, fraud_detector):
        """Test calculation with empty signals list."""
        score = fraud_detector._calculate_risk_score([])
        assert score == 0.0
    
    def test_single_signal(self, fraud_detector):
        """Test calculation with single signal."""
        signals = [
            FraudSignal(name="URL Similarity", score=80.0, description="Test")
        ]
        score = fraud_detector._calculate_risk_score(signals)
        assert 0 <= score <= 100
        assert score > 0
    
    def test_weighted_average_calculation(self, fraud_detector):
        """Test that weighted average is calculated correctly."""
        signals = [
            FraudSignal(name="URL Similarity", score=100.0, description="High similarity"),
            FraudSignal(name="Domain Age", score=90.0, description="New domain"),
            FraudSignal(name="SSL/HTTPS", score=0.0, description="Valid SSL"),
            FraudSignal(name="Keyword Pattern", score=0.0, description="No keywords"),
        ]
        score = fraud_detector._calculate_risk_score(signals)
        # URL Similarity (0.4) * 100 + Domain Age (0.3) * 90 = 40 + 27 = 67
        # Weighted average should be around 67
        assert 60 <= score <= 75  # Allow some margin
    
    def test_all_signals_high_score(self, fraud_detector):
        """Test calculation when all signals indicate high risk."""
        signals = [
            FraudSignal(name="URL Similarity", score=100.0, description="Test"),
            FraudSignal(name="Domain Age", score=90.0, description="Test"),
            FraudSignal(name="SSL/HTTPS", score=90.0, description="Test"),
            FraudSignal(name="Keyword Pattern", score=100.0, description="Test"),
        ]
        score = fraud_detector._calculate_risk_score(signals)
        assert score > 80
        assert score <= 100
    
    def test_all_signals_low_score(self, fraud_detector):
        """Test calculation when all signals indicate low risk."""
        signals = [
            FraudSignal(name="URL Similarity", score=0.0, description="Test"),
            FraudSignal(name="Domain Age", score=0.0, description="Test"),
            FraudSignal(name="SSL/HTTPS", score=0.0, description="Test"),
            FraudSignal(name="Keyword Pattern", score=0.0, description="Test"),
        ]
        score = fraud_detector._calculate_risk_score(signals)
        assert score == 0.0
    
    def test_score_capped_at_100(self, fraud_detector):
        """Test that risk score is capped at 100."""
        # FraudSignal validation prevents scores > 100, so we test with a high but valid score
        # and verify the calculation caps it
        signals = [
            FraudSignal(name="URL Similarity", score=100.0, description="Test"),
            FraudSignal(name="Domain Age", score=100.0, description="Test"),
            FraudSignal(name="SSL/HTTPS", score=100.0, description="Test"),
            FraudSignal(name="Keyword Pattern", score=100.0, description="Test"),
        ]
        score = fraud_detector._calculate_risk_score(signals)
        assert score <= 100
    
    def test_unknown_signal_weight(self, fraud_detector):
        """Test calculation with unknown signal name (uses default weight)."""
        signals = [
            FraudSignal(name="Unknown Signal", score=50.0, description="Test")
        ]
        score = fraud_detector._calculate_risk_score(signals)
        assert 0 <= score <= 100


class TestExplanationGeneration:
    """Test explanation generation from risk score and signals."""
    
    def test_safe_explanation(self, fraud_detector):
        """Test explanation for safe websites."""
        signals = [
            FraudSignal(name="URL Similarity", score=10.0, description="Low similarity"),
            FraudSignal(name="Domain Age", score=0.0, description="Old domain"),
        ]
        explanation = fraud_detector._generate_explanation(20.0, signals)
        assert "appears to be safe" in explanation.lower()
    
    def test_suspicious_explanation(self, fraud_detector):
        """Test explanation for suspicious websites."""
        signals = [
            FraudSignal(name="URL Similarity", score=50.0, description="Moderate similarity"),
        ]
        explanation = fraud_detector._generate_explanation(50.0, signals)
        assert "suspicious" in explanation.lower()
    
    def test_dangerous_explanation(self, fraud_detector):
        """Test explanation for dangerous websites."""
        signals = [
            FraudSignal(name="URL Similarity", score=90.0, description="High similarity"),
            FraudSignal(name="Domain Age", score=90.0, description="New domain"),
        ]
        explanation = fraud_detector._generate_explanation(85.0, signals)
        assert "potential fraud" in explanation.lower() or "fraud" in explanation.lower()
    
    def test_explanation_includes_significant_signals(self, fraud_detector):
        """Test that explanation includes details about significant signals."""
        signals = [
            FraudSignal(name="URL Similarity", score=80.0, description="High similarity to chase.com"),
            FraudSignal(name="Domain Age", score=5.0, description="Old domain"),
        ]
        explanation = fraud_detector._generate_explanation(50.0, signals)
        assert "High similarity" in explanation or "chase.com" in explanation
    
    def test_explanation_limits_signal_details(self, fraud_detector):
        """Test that explanation limits to top 2 significant signals."""
        signals = [
            FraudSignal(name="URL Similarity", score=80.0, description="Signal 1"),
            FraudSignal(name="Domain Age", score=70.0, description="Signal 2"),
            FraudSignal(name="SSL/HTTPS", score=60.0, description="Signal 3"),
        ]
        explanation = fraud_detector._generate_explanation(70.0, signals)
        # Should include at most 2 signals
        signal_count = explanation.count("Signal")
        assert signal_count <= 2


class TestRiskLevelClassification:
    """Test risk level classification."""
    
    def test_safe_risk_level(self, fraud_detector):
        """Test classification as Safe."""
        level = fraud_detector.get_risk_level(25.0)
        assert level == RiskLevel.SAFE
    
    def test_suspicious_risk_level(self, fraud_detector):
        """Test classification as Suspicious."""
        level = fraud_detector.get_risk_level(50.0)
        assert level == RiskLevel.SUSPICIOUS
    
    def test_dangerous_risk_level(self, fraud_detector):
        """Test classification as Dangerous."""
        level = fraud_detector.get_risk_level(85.0)
        assert level == RiskLevel.DANGEROUS
    
    def test_boundary_safe_threshold(self, fraud_detector):
        """Test classification at safe threshold boundary."""
        level = fraud_detector.get_risk_level(30.0)
        assert level == RiskLevel.SAFE
    
    def test_boundary_suspicious_threshold(self, fraud_detector):
        """Test classification at suspicious threshold boundary."""
        level = fraud_detector.get_risk_level(70.0)
        assert level == RiskLevel.SUSPICIOUS
    
    def test_custom_thresholds(self, fraud_detector_custom):
        """Test classification with custom thresholds."""
        level = fraud_detector_custom.get_risk_level(25.0)
        assert level == RiskLevel.SUSPICIOUS  # Custom threshold is 20
    
    def test_zero_risk_score(self, fraud_detector):
        """Test classification with zero risk score."""
        level = fraud_detector.get_risk_level(0.0)
        assert level == RiskLevel.SAFE
    
    def test_max_risk_score(self, fraud_detector):
        """Test classification with maximum risk score."""
        level = fraud_detector.get_risk_level(100.0)
        assert level == RiskLevel.DANGEROUS


class TestRecommendations:
    """Test user recommendations based on risk level."""
    
    def test_safe_recommendation(self, fraud_detector):
        """Test recommendation for safe websites."""
        recommendation = fraud_detector.get_recommendation(RiskLevel.SAFE)
        assert "safe" in recommendation.lower()
        assert "proceed" in recommendation.lower()
    
    def test_suspicious_recommendation(self, fraud_detector):
        """Test recommendation for suspicious websites."""
        recommendation = fraud_detector.get_recommendation(RiskLevel.SUSPICIOUS)
        assert "caution" in recommendation.lower()
        assert "verify" in recommendation.lower()
    
    def test_dangerous_recommendation(self, fraud_detector):
        """Test recommendation for dangerous websites."""
        recommendation = fraud_detector.get_recommendation(RiskLevel.DANGEROUS)
        assert "do not" in recommendation.lower() or "not" in recommendation.lower()
        assert "exit" in recommendation.lower() or "immediately" in recommendation.lower()


class TestFullAnalysis:
    """Test complete URL analysis workflow."""
    
    @patch('server.fraud_detector.whois.whois')
    @patch('server.fraud_detector.socket.create_connection')
    @patch('server.fraud_detector.ssl.create_default_context')
    def test_analyze_safe_url(self, mock_ssl_ctx, mock_conn, mock_whois, fraud_detector):
        """Test analysis of a safe URL."""
        # Mock WHOIS - old domain
        mock_whois_record = Mock()
        mock_whois_record.creation_date = datetime.now() - timedelta(days=365)
        mock_whois.return_value = mock_whois_record
        
        # Mock SSL - valid certificate
        mock_ssl_sock = Mock()
        expiry_date = datetime.utcnow() + timedelta(days=90)
        mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
        mock_ssl_sock.getpeercert.return_value = mock_cert
        
        mock_context = Mock()
        mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
        mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
        mock_ssl_ctx.return_value = mock_context
        
        mock_sock = Mock()
        mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = Mock(return_value=False)
        
        risk_score, signals, explanation = fraud_detector.analyze_url("https://example.com")
        
        assert isinstance(risk_score, float)
        assert 0 <= risk_score <= 100
        assert len(signals) == 4  # All 4 signal types
        assert isinstance(explanation, str)
        assert len(explanation) > 0
    
    @patch('server.fraud_detector.whois.whois')
    @patch('server.fraud_detector.socket.create_connection')
    @patch('server.fraud_detector.ssl.create_default_context')
    def test_analyze_suspicious_url(self, mock_ssl_ctx, mock_conn, mock_whois, fraud_detector):
        """Test analysis of a suspicious URL."""
        # Mock WHOIS - new domain
        mock_whois_record = Mock()
        mock_whois_record.creation_date = datetime.now() - timedelta(days=15)
        mock_whois.return_value = mock_whois_record
        
        # Mock SSL - valid certificate
        mock_ssl_sock = Mock()
        expiry_date = datetime.utcnow() + timedelta(days=90)
        mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
        mock_ssl_sock.getpeercert.return_value = mock_cert
        
        mock_context = Mock()
        mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
        mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
        mock_ssl_ctx.return_value = mock_context
        
        mock_sock = Mock()
        mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = Mock(return_value=False)
        
        risk_score, signals, explanation = fraud_detector.analyze_url(
            "https://chase-bank.com/secure-login"
        )
        
        assert risk_score > 30  # Should be suspicious
        assert len(signals) == 4
        assert any(s.score > 0 for s in signals)  # At least one signal triggered
    
    def test_analyze_url_with_http(self, fraud_detector):
        """Test analysis of HTTP (non-HTTPS) URL."""
        with patch('server.fraud_detector.whois.whois') as mock_whois:
            mock_whois_record = Mock()
            mock_whois_record.creation_date = datetime.now() - timedelta(days=365)
            mock_whois.return_value = mock_whois_record
            
            risk_score, signals, explanation = fraud_detector.analyze_url("http://example.com")
            
            # Should have SSL signal indicating no HTTPS
            ssl_signal = next((s for s in signals if s.name == "SSL/HTTPS"), None)
            assert ssl_signal is not None
            assert ssl_signal.score == 60.0
    
    def test_analyze_url_domain_normalization(self, fraud_detector):
        """Test that URL analysis normalizes domain correctly."""
        with patch('server.fraud_detector.whois.whois') as mock_whois, \
             patch('server.fraud_detector.socket.create_connection') as mock_conn, \
             patch('server.fraud_detector.ssl.create_default_context') as mock_ssl_ctx:
            
            mock_whois_record = Mock()
            mock_whois_record.creation_date = datetime.now() - timedelta(days=365)
            mock_whois.return_value = mock_whois_record
            
            mock_ssl_sock = Mock()
            expiry_date = datetime.utcnow() + timedelta(days=90)
            mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
            mock_ssl_sock.getpeercert.return_value = mock_cert
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            mock_ssl_ctx.return_value = mock_context
            
            mock_sock = Mock()
            mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = Mock(return_value=False)
            
            # URL with www and port
            risk_score, signals, explanation = fraud_detector.analyze_url(
                "https://www.example.com:443/page"
            )
            
            # Should normalize domain correctly
            assert isinstance(risk_score, float)
            assert len(signals) == 4


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_url(self, fraud_detector):
        """Test handling of empty URL."""
        # Empty URL should fail URL parsing
        with pytest.raises((ValueError, Exception)):
            fraud_detector.analyze_url("")
    
    def test_invalid_url_format(self, fraud_detector):
        """Test handling of invalid URL format."""
        # Invalid URL format may not raise exception if urlparse handles it
        # It might return empty netloc, which would cause issues in domain checks
        with pytest.raises((ValueError, Exception)):
            fraud_detector.analyze_url("not-a-url")
    
    def test_url_with_special_characters(self, fraud_detector):
        """Test handling of URLs with special characters."""
        with patch('server.fraud_detector.whois.whois') as mock_whois, \
             patch('server.fraud_detector.socket.create_connection') as mock_conn, \
             patch('server.fraud_detector.ssl.create_default_context') as mock_ssl_ctx:
            
            mock_whois_record = Mock()
            mock_whois_record.creation_date = datetime.now() - timedelta(days=365)
            mock_whois.return_value = mock_whois_record
            
            mock_ssl_sock = Mock()
            expiry_date = datetime.utcnow() + timedelta(days=90)
            mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
            mock_ssl_sock.getpeercert.return_value = mock_cert
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            mock_ssl_ctx.return_value = mock_context
            
            mock_sock = Mock()
            mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = Mock(return_value=False)
            
            # URL with query parameters and fragments
            risk_score, signals, explanation = fraud_detector.analyze_url(
                "https://example.com/page?param=value&other=123#fragment"
            )
            assert isinstance(risk_score, float)
    
    def test_very_long_url(self, fraud_detector):
        """Test handling of very long URLs."""
        long_path = "/" + "a" * 2000
        url = f"https://example.com{long_path}"
        
        with patch('server.fraud_detector.whois.whois') as mock_whois, \
             patch('server.fraud_detector.socket.create_connection') as mock_conn, \
             patch('server.fraud_detector.ssl.create_default_context') as mock_ssl_ctx:
            
            mock_whois_record = Mock()
            mock_whois_record.creation_date = datetime.now() - timedelta(days=365)
            mock_whois.return_value = mock_whois_record
            
            mock_ssl_sock = Mock()
            expiry_date = datetime.utcnow() + timedelta(days=90)
            mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
            mock_ssl_sock.getpeercert.return_value = mock_cert
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            mock_ssl_ctx.return_value = mock_context
            
            mock_sock = Mock()
            mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = Mock(return_value=False)
            
            risk_score, signals, explanation = fraud_detector.analyze_url(url)
            assert isinstance(risk_score, float)
    
    def test_international_domain(self, fraud_detector):
        """Test handling of international domain names."""
        with patch('server.fraud_detector.whois.whois') as mock_whois, \
             patch('server.fraud_detector.socket.create_connection') as mock_conn, \
             patch('server.fraud_detector.ssl.create_default_context') as mock_ssl_ctx:
            
            mock_whois_record = Mock()
            mock_whois_record.creation_date = datetime.now() - timedelta(days=365)
            mock_whois.return_value = mock_whois_record
            
            mock_ssl_sock = Mock()
            expiry_date = datetime.utcnow() + timedelta(days=90)
            mock_cert = {"notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT")}
            mock_ssl_sock.getpeercert.return_value = mock_cert
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
            mock_ssl_ctx.return_value = mock_context
            
            mock_sock = Mock()
            mock_conn.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = Mock(return_value=False)
            
            # IDN domain (example)
            risk_score, signals, explanation = fraud_detector.analyze_url("https://пример.рф")
            assert isinstance(risk_score, float)

