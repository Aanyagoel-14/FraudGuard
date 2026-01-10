"""
Pytest configuration and shared fixtures.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add project root to path so we can import server as a package
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import from server package
from server.fraud_detector import FraudDetector
from server.models import FraudSignal, RiskLevel


@pytest.fixture
def fraud_detector():
    """Create a FraudDetector instance with default thresholds."""
    return FraudDetector(safe_threshold=30, suspicious_threshold=70)


@pytest.fixture
def fraud_detector_custom():
    """Create a FraudDetector instance with custom thresholds."""
    return FraudDetector(safe_threshold=20, suspicious_threshold=60)


@pytest.fixture
def mock_whois_record():
    """Mock WHOIS record for testing."""
    record = Mock()
    record.creation_date = datetime.now() - timedelta(days=100)
    return record


@pytest.fixture
def mock_whois_record_new():
    """Mock WHOIS record for a new domain (< 30 days)."""
    record = Mock()
    record.creation_date = datetime.now() - timedelta(days=15)
    return record


@pytest.fixture
def mock_whois_record_old():
    """Mock WHOIS record for an old domain (> 180 days)."""
    record = Mock()
    record.creation_date = datetime.now() - timedelta(days=365)
    return record


@pytest.fixture
def mock_ssl_cert_valid():
    """Mock valid SSL certificate."""
    cert = {
        "notAfter": (datetime.utcnow() + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")
    }
    return cert


@pytest.fixture
def mock_ssl_cert_expired():
    """Mock expired SSL certificate."""
    cert = {
        "notAfter": (datetime.utcnow() - timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    }
    return cert


@pytest.fixture
def mock_ssl_cert_expiring_soon():
    """Mock SSL certificate expiring soon."""
    cert = {
        "notAfter": (datetime.utcnow() + timedelta(days=15)).strftime("%b %d %H:%M:%S %Y GMT")
    }
    return cert

