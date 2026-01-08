"""
Core fraud detection engine.
Implements various fraud detection algorithms and signal analysis.
"""
from typing import List, Optional
from urllib.parse import urlparse
import difflib
import ssl
import socket
from datetime import datetime

import whois

from .models import FraudSignal, RiskLevel


class FraudDetector:
    """Main fraud detection engine."""
    
    # Known legitimate bank and payment domains
    LEGITIMATE_DOMAINS = [
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citibank.com",
        "usbank.com",
        "pnc.com",
        "capitalone.com",
        "tdbank.com",
        "paypal.com",
        "stripe.com",
        "square.com",
        "venmo.com",
        "zelle.com",
    ]
    
    # Phishing keywords commonly used in fraudulent sites
    PHISHING_KEYWORDS = [
        "secure-login",
        "verify-account",
        "update-info",
        "suspended-account",
        "urgent-action",
        "confirm-identity",
        "security-alert",
        "account-locked",
        "verify-now",
        "immediate-action",
    ]
    
    def __init__(self, safe_threshold: int, suspicious_threshold: int):
        """Initialize the fraud detector with configurable thresholds."""
        self.safe_threshold = safe_threshold
        self.suspicious_threshold = suspicious_threshold
    
    def analyze_url(self, url: str) -> tuple[float, List[FraudSignal], str]:
        """
        Analyze a URL for fraud risk.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Tuple of (risk_score, signals, explanation)
        """
        signals: List[FraudSignal] = []
        
        # Extract domain from URL
        parsed_url = urlparse(url)
        domain = self._normalize_domain(parsed_url.netloc)
        
        # 1. URL Similarity Analysis
        similarity_signal = self._check_url_similarity(domain)
        signals.append(similarity_signal)
        
        # 2. Domain Age Check using WHOIS
        age_signal = self._check_domain_age(domain)
        signals.append(age_signal)
        
        # 3. HTTPS/SSL Validation
        ssl_signal = self._check_ssl(domain, url)
        signals.append(ssl_signal)
        
        # 4. Keyword Pattern Detection
        keyword_signal = self._check_keywords(url)
        signals.append(keyword_signal)
        
        # Calculate overall risk score (weighted average)
        risk_score = self._calculate_risk_score(signals)
        
        # Generate explanation
        explanation = self._generate_explanation(risk_score, signals)
        
        return risk_score, signals, explanation
    
    def _normalize_domain(self, netloc: str) -> str:
        """Normalize domain by removing ports and leading www."""
        domain = netloc.lower().split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    
    def _check_url_similarity(self, domain: str) -> FraudSignal:
        """
        Check URL similarity against known legitimate domains.
        
        Returns:
            FraudSignal with similarity analysis
        """
        max_similarity = 0.0
        most_similar_domain = ""
        
        for legit_domain in self.LEGITIMATE_DOMAINS:
            similarity = difflib.SequenceMatcher(None, domain, legit_domain).ratio()
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_domain = legit_domain
        
        # High similarity (>0.7) with different domain is suspicious
        if max_similarity > 0.7 and domain != most_similar_domain:
            score = min(100, max_similarity * 100)
            description = (
                f"Domain '{domain}' shows {max_similarity:.1%} similarity to legitimate "
                f"domain '{most_similar_domain}'"
            )
        elif max_similarity > 0.5:
            score = max_similarity * 50  # Lower score for moderate similarity
            description = f"Domain '{domain}' shows moderate similarity to known bank domains"
        else:
            score = 0
            description = f"Domain '{domain}' does not match known bank patterns"
        
        return FraudSignal(
            name="URL Similarity",
            score=score,
            description=description
        )
    
    def _check_domain_age(self, domain: str) -> FraudSignal:
        """
        Check domain age using WHOIS data.
        New domains are more likely to be fraudulent.
        """
        try:
            record = whois.whois(domain)
            creation_date = self._coerce_datetime(record.creation_date)
            if not creation_date:
                raise ValueError("Creation date unavailable")
            
            age_days = (datetime.utcnow() - creation_date.replace(tzinfo=None)).days
            
            if age_days < 30:
                score = 90.0
                description = f"Domain registered {age_days} days ago ({creation_date.date()})"
            elif age_days < 180:
                score = 60.0
                description = f"Domain registered {age_days} days ago ({creation_date.date()})"
            else:
                score = 0.0
                description = f"Domain age {age_days} days - considered seasoned"
        except Exception as exc:
            # In many environments WHOIS lookups can fail (rate limits, missing TLD support, etc.).
            # To avoid false positives for normal sites, we treat this as a neutral signal.
            score = 0.0
            description = f"Could not verify domain age ({exc}); treated as neutral for risk scoring"
        
        return FraudSignal(
            name="Domain Age",
            score=score,
            description=description
        )
    
    def _check_ssl(self, domain: str, url: str) -> FraudSignal:
        """
        Check SSL/HTTPS certificate validity.
        """
        if not url.startswith("https://"):
            return FraudSignal(
                name="SSL/HTTPS",
                score=60.0,
                description="URL does not use HTTPS - data transmission is insecure"
            )
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            not_after = cert.get("notAfter")
            if not not_after:
                raise ValueError("Certificate missing expiry")
            
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            
            if days_left < 0:
                score = 90.0
                description = "SSL certificate is expired"
            elif days_left < 30:
                score = 50.0
                description = f"SSL certificate expires soon ({days_left} days)"
            else:
                score = 0.0
                description = f"Valid SSL certificate; expires in {days_left} days"
        except Exception as exc:
            # Network / SSL inspection can fail locally (firewalls, captive portals, etc.).
            # To reduce false positives, treat inability to validate SSL as neutral.
            score = 0.0
            description = f"Could not validate SSL certificate ({exc}); treated as neutral for risk scoring"
        
        return FraudSignal(
            name="SSL/HTTPS",
            score=score,
            description=description
        )
    
    def _check_keywords(self, url: str) -> FraudSignal:
        """
        Check for phishing keywords in URL.
        """
        url_lower = url.lower()
        found_keywords = [keyword for keyword in self.PHISHING_KEYWORDS if keyword in url_lower]
        
        if found_keywords:
            score = min(100, len(found_keywords) * 20)
            description = f"Found suspicious keywords in URL: {', '.join(found_keywords)}"
        else:
            score = 0
            description = "No suspicious keywords detected in URL"
        
        return FraudSignal(
            name="Keyword Pattern",
            score=score,
            description=description
        )
    
    def _calculate_risk_score(self, signals: List[FraudSignal]) -> float:
        """
        Calculate overall risk score from individual signals.
        Uses weighted average with higher weight on critical signals.
        """
        if not signals:
            return 0.0
        
        weights = {
            "URL Similarity": 0.4,
            "Domain Age": 0.3,
            "SSL/HTTPS": 0.2,
            "Keyword Pattern": 0.1,
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for signal in signals:
            weight = weights.get(signal.name, 0.1)
            weighted_sum += signal.score * weight
            total_weight += weight
        
        return min(100, weighted_sum / total_weight if total_weight > 0 else 0)
    
    def _generate_explanation(self, risk_score: float, signals: List[FraudSignal]) -> str:
        """
        Generate human-readable explanation of the risk assessment.
        """
        if risk_score < self.safe_threshold:
            base_explanation = "This website appears to be safe based on our analysis."
        elif risk_score < self.suspicious_threshold:
            base_explanation = "This website shows some suspicious characteristics."
        else:
            base_explanation = "This website shows multiple indicators of potential fraud."
        
        significant_signals = [s for s in signals if s.score > 30]
        if significant_signals:
            details = " Key concerns: " + "; ".join([s.description for s in significant_signals[:2]])
            base_explanation += details
        
        return base_explanation
    
    def get_risk_level(self, risk_score: float) -> RiskLevel:
        """
        Determine risk level from risk score.
        """
        if risk_score <= self.safe_threshold:
            return RiskLevel.SAFE
        elif risk_score <= self.suspicious_threshold:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.DANGEROUS
    
    def get_recommendation(self, risk_level: RiskLevel) -> str:
        """
        Get user recommendation based on risk level.
        """
        if risk_level == RiskLevel.SAFE:
            return "This site appears safe. Proceed with normal caution."
        elif risk_level == RiskLevel.SUSPICIOUS:
            return "Exercise caution. Verify the website's authenticity before entering sensitive information."
        else:
            return "Do not enter any personal or financial information. Exit this site immediately and report if possible."
    
    def _coerce_datetime(self, value: Optional[object]) -> Optional[datetime]:
        """Normalize WHOIS creation_date values that can be list/str/datetime."""
        if isinstance(value, list) and value:
            value = value[0]
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y.%m.%d %H:%M:%S"):
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
        return None

