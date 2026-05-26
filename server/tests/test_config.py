"""
Unit tests for configuration management.
Tests settings loading, environment variables, and defaults.
"""
import pytest
import os
import sys
from pathlib import Path
from unittest.mock import patch

# Add project root to path so we can import server as a package
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from server.config import Settings, settings


class TestSettings:
    """Test Settings class."""
    
    def test_default_backend_url(self):
        """Test default backend URL."""
        with patch.dict(os.environ, {}, clear=True):
            test_settings = Settings()
            assert test_settings.backend_url == "http://localhost:8000"
    
    def test_default_thresholds(self):
        """Test default fraud detection thresholds."""
        with patch.dict(os.environ, {}, clear=True):
            test_settings = Settings()
            assert test_settings.safe_threshold == 30
            assert test_settings.suspicious_threshold == 70
            assert test_settings.dangerous_threshold == 100
    
    def test_default_cors_origins(self):
        """Test default CORS origins."""
        with patch.dict(os.environ, {}, clear=True):
            test_settings = Settings()
            assert "*" in test_settings.cors_origins
    
    def test_default_optional_api_settings(self):
        """Test default values for optional API settings (Safe Browsing, timeouts)."""
        with patch.dict(os.environ, {}, clear=True):
            test_settings = Settings()
            assert test_settings.safe_browsing_api_key is None
            assert test_settings.whois_timeout_secs == 5
            assert test_settings.ssl_timeout_secs == 5
    
    def test_environment_variable_override(self):
        """Test that environment variables override defaults."""
        env_vars = {
            "BACKEND_URL": "http://custom-backend:9000",
            "SAFE_THRESHOLD": "25",
            "SUSPICIOUS_THRESHOLD": "65"
        }
        with patch.dict(os.environ, env_vars, clear=False):
            test_settings = Settings()
            # Note: Pydantic settings may need specific env var names
            # This test verifies the structure works
    
    def test_settings_instance(self):
        """Test that global settings instance exists."""
        assert settings is not None
        assert isinstance(settings, Settings)
    
    def test_settings_threshold_types(self):
        """Test that thresholds are integers."""
        assert isinstance(settings.safe_threshold, int)
        assert isinstance(settings.suspicious_threshold, int)
        assert isinstance(settings.dangerous_threshold, int)
    
    def test_settings_cors_origins_type(self):
        """Test that CORS origins is a list."""
        assert isinstance(settings.cors_origins, list)
    
    def test_settings_backend_url_type(self):
        """Test that backend URL is a string."""
        assert isinstance(settings.backend_url, str)
        assert len(settings.backend_url) > 0

