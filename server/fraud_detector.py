"""
Core fraud detection engine.
Implements URL-based fraud detection signals and weighted risk scoring.

All signals are derived purely from the URL string and publicly available
URL-metadata (WHOIS, SSL certificate). No page content is inspected.
"""
import re
import ssl
import socket
import logging
import difflib
import requests
from typing import List, Optional
from urllib.parse import urlparse
from datetime import datetime

import whois

from .models import FraudSignal, RiskLevel

logger = logging.getLogger(__name__)


class FraudDetector:
    """
    URL-based fraud detection engine.

    Evaluates 6 independent signals derived from a URL, combines them via
    weighted average, and returns a risk score in [0, 100].

    Signal weights (Phase 2 — 6 signals):
        URL Similarity  : 0.25
        Domain Age      : 0.20
        SSL/HTTPS       : 0.15
        Keyword Pattern : 0.10
        URL Structure   : 0.10
        Safe Browsing   : 0.20  (skipped gracefully if API key not set)
    """

    # ------------------------------------------------------------------ #
    #  Known legitimate banking and payment domains used for typosquatting
    #  detection via string-similarity comparison.
    #  Scope: banking and payment institutions only (per system vision).
    # ------------------------------------------------------------------ #
    LEGITIMATE_DOMAINS = [
        # US banks
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citibank.com",
        "usbank.com",
        "pnc.com",
        "capitalone.com",
        "tdbank.com",
        "regions.com",
        "fifththird.com",
        "suntrust.com",
        "bbt.com",
        "keybank.com",
        "huntington.com",
        "ally.com",
        # Payment processors
        "paypal.com",
        "stripe.com",
        "square.com",
        "venmo.com",
        "zelle.com",
        "cashapp.com",
        "wise.com",
        "revolut.com",
        "skrill.com",
        "payoneer.com",
        # Indian banks
        "icicibank.com",
        "sbi.co.in",
        "hdfcbank.com",
        "axisbank.com",
        "kotakbank.com",
        "yesbank.in",
        "indusind.com",
        "federalbank.co.in",
        # Global banks
        "hsbc.com",
        "barclays.co.uk",
        "barclays.com",
        "deutschebank.com",
        "bnpparibas.com",
        "scotiabank.com",
        "rbc.com",
        "lloydsbank.com",
        "santander.com",
        "ing.com",
        # Digital payment (India & global)
        "googlepay.com",
        "phonepe.com",
        "razorpay.com",
        "paytm.com",
        "bhim.org",
        # Legacy list entries preserved
        "americanexpress.com",
        "hdfc.com",
        "axis.com",
    ]

    # ------------------------------------------------------------------ #
    #  Phishing keyword patterns checked against the full URL string.
    #  Includes both hyphenated and non-hyphenated variants.
    # ------------------------------------------------------------------ #
    PHISHING_KEYWORDS = [
        # Hyphenated variants
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
        "password-reset",
        "billing-update",
        "unusual-activity",
        "confirm-payment",
        "limited-access",
        # Non-hyphenated variants (bypass the hyphen check)
        "securelogin",
        "verifyaccount",
        "updateinfo",
        "accountlocked",
        "verifynow",
        # Additional financial-context patterns
        "signin-verify",
        "login-secure",
        "reactivate-account",
        "unlock-account",
    ]

    # ------------------------------------------------------------------ #
    #  Free-abuse TLDs strongly associated with phishing campaigns.
    # ------------------------------------------------------------------ #
    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".xyz", ".top", ".buzz", ".click", ".link",
        ".work", ".date", ".racing", ".win", ".bid",
    }

    # Banking-related terms used to boost moderate-similarity scores
    _BANKING_KEYWORDS = [
        "bank", "pay", "secure", "verify", "chase", "wells",
        "citi", "paypal", "signin", "login", "account",
    ]

    def __init__(
        self,
        safe_threshold: int,
        suspicious_threshold: int,
        safe_browsing_api_key: Optional[str] = None,
        ssl_timeout: int = 5,
        whois_timeout: int = 5,
    ):
        self.safe_threshold = safe_threshold
        self.suspicious_threshold = suspicious_threshold
        self.safe_browsing_api_key = safe_browsing_api_key
        self.ssl_timeout = ssl_timeout
        self.whois_timeout = whois_timeout

    # ================================================================== #
    #  Public API
    # ================================================================== #

    def analyze_url(self, url: str) -> tuple[float, List[FraudSignal], str]:
        """
        Analyze a URL for fraud risk using all available signals.

        Returns:
            Tuple of (risk_score, signals, explanation)
        """
        if not url or not url.strip():
            raise ValueError("URL cannot be empty")

        parsed = urlparse(url)
        domain = self._normalize_domain(parsed.netloc)

        if not domain or not parsed.scheme:
            raise ValueError(f"Invalid URL format: {url}")

        signals: List[FraudSignal] = []

        # Signal 1 — URL Similarity (typosquatting detection)
        signals.append(self._check_url_similarity(domain))

        # Signal 2 — Domain Age via WHOIS
        signals.append(self._check_domain_age(domain))

        # Signal 3 — SSL/HTTPS certificate validity
        signals.append(self._check_ssl(domain, url))

        # Signal 4 — Phishing keyword patterns in URL
        signals.append(self._check_keywords(url))

        # Signal 5 — URL structural anomalies (TLD, depth, length, IP)
        signals.append(self._check_url_structure(domain, url))

        # Signal 6 — Google Safe Browsing lookup (skipped if key not set)
        signals.append(self._check_safe_browsing(url))

        risk_score = self._calculate_risk_score(signals)
        explanation = self._generate_explanation(risk_score, signals)

        return risk_score, signals, explanation

    # ================================================================== #
    #  Signal implementations
    # ================================================================== #

    def _check_url_similarity(self, domain: str) -> FraudSignal:
        """
        Signal 1 — URL Similarity (weight 0.25)

        Compare the domain against known legitimate banking/payment domains
        using SequenceMatcher. Penalizes typosquatting and character-swap attacks.
        Exact matches on the legitimate list score 0.
        """
        # Exact match — definitely legitimate
        if domain in self.LEGITIMATE_DOMAINS:
            return FraudSignal(
                name="URL Similarity",
                score=0.0,
                description=f"Domain '{domain}' matches a known legitimate domain",
            )

        max_similarity = 0.0
        most_similar = ""
        contains_legit_name = False

        has_banking_kw = any(kw in domain for kw in self._BANKING_KEYWORDS)

        # The base name of the query domain (without TLD), used for prefix checks below.
        query_base = domain.rsplit(".", 1)[0]  # 'google.com' → 'google'

        for legit in self.LEGITIMATE_DOMAINS:
            legit_base = legit.rsplit(".", 1)[0]  # 'googlepay.com' → 'googlepay'

            # Skip parent-brand comparisons: if the legitimate domain is an EXTENSION
            # of the query domain name, the query is the parent brand, not an impersonator.
            # Example: 'google.com' must not be flagged for similarity to 'googlepay.com'.
            if legit_base != query_base and legit_base.startswith(query_base):
                continue

            ratio = difflib.SequenceMatcher(None, domain, legit).ratio()
            if ratio > max_similarity:
                max_similarity = ratio
                most_similar = legit

            # Check if domain embeds a legitimate name (e.g. "paypal" in "paypal-secure.com")
            legit_name = legit_base  # already without TLD
            if legit_name in domain and domain != legit:
                contains_legit_name = True

        # Double-check exact match (shouldn't happen but be safe)
        if domain == most_similar:
            return FraudSignal(
                name="URL Similarity",
                score=0.0,
                description=f"Domain '{domain}' matches a known legitimate domain",
            )

        if max_similarity > 0.85:
            # Very high similarity (85-100%) — strong typosquatting indicator.
            # Starts at 60 (not 0) so even borderline 85-90% similarity produces
            # a meaningfully high score for a banking domain lookalike.
            score = 60.0 + ((max_similarity - 0.85) / 0.15) * 40.0
            description = (
                f"Domain '{domain}' shows {max_similarity:.1%} similarity to "
                f"'{most_similar}' — high risk of typosquatting"
            )
        elif max_similarity > 0.75:
            # High similarity (75-85%): score 35-60
            score = 35.0 + ((max_similarity - 0.75) / 0.10) * 25.0
            description = (
                f"Domain '{domain}' shows {max_similarity:.1%} similarity to "
                f"'{most_similar}' — potential typosquatting"
            )
        elif max_similarity > 0.65 and (has_banking_kw or contains_legit_name):
            score = 20.0 + ((max_similarity - 0.65) / 0.10) * 15.0
            description = f"Domain '{domain}' shows moderate similarity to known banking domains"
        elif max_similarity > 0.65:
            score = 10.0 + ((max_similarity - 0.65) / 0.10) * 10.0
            description = f"Domain '{domain}' shows some similarity to known banking domains"
        else:
            score = 0.0
            description = f"Domain '{domain}' does not closely match known banking patterns"

        # If the domain EMBEDS a legitimate banking name as a substring
        # (e.g., 'paypal' in 'paypal-login.com'), force the score high
        # regardless of the sequence similarity metric.
        if contains_legit_name:
            score = max(score, 70.0)
            if score >= 70.0 and "similarity" not in description:
                description = (
                    f"Domain '{domain}' contains the name of a known legitimate "
                    f"banking domain — strong typosquatting indicator"
                )

        return FraudSignal(name="URL Similarity", score=score, description=description)

    def _check_domain_age(self, domain: str) -> FraudSignal:
        """
        Signal 2 — Domain Age (weight 0.20)

        New domains are more likely to be fraudulent.
        On WHOIS lookup failure the score is 15 (neutral) — not 90.
        """
        try:
            record = whois.whois(domain)
            creation_date = self._coerce_datetime(record.creation_date)
            if not creation_date:
                raise ValueError("Creation date unavailable in WHOIS record")

            age_days = (datetime.utcnow() - creation_date.replace(tzinfo=None)).days

            if age_days < 30:
                score = 90.0
                description = f"Domain registered only {age_days} days ago — very new"
            elif age_days < 180:
                score = 60.0
                description = f"Domain registered {age_days} days ago — relatively new"
            else:
                score = 0.0
                description = f"Domain age {age_days} days — established domain"

        except Exception as exc:
            # WHOIS lookups fail frequently: rate limits, unsupported TLDs, network
            # issues. Treat as genuinely neutral — do not inflate to high risk.
            score = 15.0
            description = f"Could not verify domain age ({exc}); treated as neutral"
            logger.debug("WHOIS lookup failed for %s: %s", domain, exc)

        return FraudSignal(name="Domain Age", score=score, description=description)

    def _check_ssl(self, domain: str, url: str) -> FraudSignal:
        """
        Signal 3 — SSL/HTTPS (weight 0.15)

        Validates the SSL certificate. On connection failure the score is 15
        (neutral) — not 90.
        """
        if not url.startswith("https://"):
            return FraudSignal(
                name="SSL/HTTPS",
                score=60.0,
                description="URL does not use HTTPS — data transmission is insecure",
            )

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.ssl_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

            not_after = cert.get("notAfter")
            if not not_after:
                raise ValueError("Certificate missing expiry field")

            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days

            if days_left < 0:
                score = 90.0
                description = "SSL certificate is expired"
            elif days_left < 30:
                score = 50.0
                description = f"SSL certificate expires in {days_left} days — expiring soon"
            else:
                score = 0.0
                description = f"Valid SSL certificate; expires in {days_left} days"

        except Exception as exc:
            # SSL validation can fail due to firewalls, local proxies, captive portals.
            # Treat inability to validate as neutral — do not inflate to high risk.
            score = 15.0
            description = f"Could not validate SSL certificate ({exc}); treated as neutral"
            logger.debug("SSL check failed for %s: %s", domain, exc)

        return FraudSignal(name="SSL/HTTPS", score=score, description=description)

    def _check_keywords(self, url: str) -> FraudSignal:
        """
        Signal 4 — Keyword Pattern (weight 0.10)

        Checks the full URL for phishing-associated keywords.
        Each matched keyword adds 20 points, capped at 100.
        """
        url_lower = url.lower()
        found = [kw for kw in self.PHISHING_KEYWORDS if kw in url_lower]

        if found:
            score = min(100.0, len(found) * 20)
            description = f"Suspicious keywords found in URL: {', '.join(found[:5])}"
            if len(found) > 5:
                description += f" (+{len(found) - 5} more)"
        else:
            score = 0.0
            description = "No suspicious keywords detected in URL"

        return FraudSignal(name="Keyword Pattern", score=score, description=description)

    def _check_url_structure(self, domain: str, url: str) -> FraudSignal:
        """
        Signal 5 — URL Structure (weight 0.10)

        Detects structural anomalies in the URL itself:
        - Free-abuse / suspicious TLDs
        - IP address used as domain name
        - Excessive subdomain depth (≥ 3 subdomain levels)
        - Excessive URL length (> 120 characters)
        """
        score = 0.0
        reasons: List[str] = []

        # Suspicious TLD
        tld_match = "." + domain.split(".")[-1].lower() if "." in domain else ""
        if tld_match in self.SUSPICIOUS_TLDS:
            score += 45.0
            reasons.append(f"Suspicious free-abuse TLD '{tld_match}'")

        # IP address as domain
        ip_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}$"
        )
        if ip_pattern.match(domain):
            score += 70.0
            reasons.append("Raw IP address used as domain name")

        # Excessive subdomain depth: 2+ subdomain levels means 4+ parts total.
        # e.g. login.secure.evil.com → 4 parts → 2 subdomain levels (login, secure)
        # Single subdomains like 'www.evil.com' (3 parts, depth=1) are normal.
        domain_parts = domain.split(".")
        subdomain_depth = max(0, len(domain_parts) - 2)
        if subdomain_depth >= 2:
            score += 25.0
            reasons.append(f"Excessive subdomain depth ({subdomain_depth} levels)")

        # Long URL — phishing URLs are often padded with random paths/tokens
        if len(url) > 120:
            score += 15.0
            reasons.append(f"Long URL ({len(url)} characters)")

        score = min(100.0, score)
        description = "; ".join(reasons) if reasons else "URL structure appears normal"

        return FraudSignal(name="URL Structure", score=score, description=description)

    def _check_safe_browsing(self, url: str) -> FraudSignal:
        """
        Signal 6 — Google Safe Browsing (weight 0.20)

        Looks up the URL against Google's Safe Browsing threat database.
        Gracefully skipped (score=0) when API key is not configured.
        On API failure, score=0 so other signals still drive the result.
        """
        if not self.safe_browsing_api_key:
            return FraudSignal(
                name="Safe Browsing",
                score=0.0,
                description="Safe Browsing not configured; signal skipped",
            )

        try:
            payload = {
                "client": {"clientId": "fraudguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                        "UNWANTED_SOFTWARE",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                f"?key={self.safe_browsing_api_key}",
                json=payload,
                timeout=5,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("matches"):
                threat_type = data["matches"][0].get("threatType", "Unknown")
                return FraudSignal(
                    name="Safe Browsing",
                    score=100.0,
                    description=f"Flagged by Google Safe Browsing: {threat_type}",
                )
            return FraudSignal(
                name="Safe Browsing",
                score=0.0,
                description="URL not found in Google Safe Browsing threat database",
            )

        except Exception as exc:
            logger.warning("Safe Browsing check failed for %s: %s", url, exc)
            return FraudSignal(
                name="Safe Browsing",
                score=0.0,
                description=f"Safe Browsing check failed ({exc}); signal skipped",
            )

    # ================================================================== #
    #  Score calculation and classification
    # ================================================================== #

    def _calculate_risk_score(self, signals: List[FraudSignal]) -> float:
        """
        Weighted average of all signal scores, with principled minimum-score
        rules that encode domain knowledge for key attack patterns.

        Weights (Phase 2 — 6 signals):
            URL Similarity  0.35   ← primary banking typosquatting signal
            Domain Age      0.25   ← new domains are highest-risk indicator
            SSL/HTTPS       0.10
            Safe Browsing   0.15   ← authoritative URL blocklist (optional)
            URL Structure   0.10
            Keyword Pattern 0.05

        Minimum-score rules (applied AFTER weighted average):
            Rule 1: URL Similarity ≥ 50  → score ≥ 31  (amber banner)
            Rule 2: URL Similarity ≥ 70  → score ≥ 50  (full overlay)
            Rule 3: URL Structure  ≥ 40  → score ≥ 31  (suspicious TLD always alerts)
            Rule 4: Safe Browsing  = 100 → score = 100 (definitive blocklist hit)
        """
        WEIGHTS = {
            "URL Similarity":  0.35,
            "Domain Age":      0.25,
            "SSL/HTTPS":       0.10,
            "Safe Browsing":   0.15,
            "URL Structure":   0.10,
            "Keyword Pattern": 0.05,
        }

        if not signals:
            return 0.0

        weighted_sum = 0.0
        total_weight = 0.0

        for signal in signals:
            weight = WEIGHTS.get(signal.name, 0.05)
            weighted_sum += signal.score * weight
            total_weight += weight

        score = min(100.0, weighted_sum / total_weight if total_weight > 0 else 0.0)

        # --- Minimum-score rules (domain-knowledge overrides) ---
        by_name = {s.name: s for s in signals}

        sim = by_name.get("URL Similarity")
        struct = by_name.get("URL Structure")
        sb = by_name.get("Safe Browsing")

        # Rule 1: High banking-domain similarity → at least amber banner
        if sim and sim.score >= 50:
            score = max(score, 31.0)

        # Rule 2: Very high banking-domain similarity → full overlay
        if sim and sim.score >= 70:
            score = max(score, 50.0)

        # Rule 3: Suspicious TLD detected → at least amber banner regardless of other signals
        if struct and struct.score >= 40:
            score = max(score, 31.0)

        # Rule 4: Confirmed Safe Browsing hit → maximum risk, no debate
        if sb and sb.score >= 100:
            score = 100.0

        return min(100.0, score)

    def get_risk_level(self, risk_score: float) -> RiskLevel:
        """Classify a numeric risk score into Safe / Suspicious / Dangerous."""
        if risk_score <= self.safe_threshold:
            return RiskLevel.SAFE
        elif risk_score <= self.suspicious_threshold:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.DANGEROUS

    def get_recommendation(self, risk_level: RiskLevel) -> str:
        """Return a user-facing recommended action for the given risk level."""
        if risk_level == RiskLevel.SAFE:
            return "This site appears safe. Proceed with normal caution."
        elif risk_level == RiskLevel.SUSPICIOUS:
            return (
                "Exercise caution. Verify the website's authenticity before "
                "entering sensitive information."
            )
        else:
            return (
                "Do not enter any personal or financial information. "
                "Exit this site immediately and consider reporting it."
            )

    def _generate_explanation(self, risk_score: float, signals: List[FraudSignal]) -> str:
        """Generate a human-readable explanation of the overall risk assessment."""
        if risk_score <= self.safe_threshold:
            base = "This website appears to be safe based on our URL analysis."
        elif risk_score <= self.suspicious_threshold:
            base = "This website shows some suspicious characteristics."
        else:
            base = "This website shows multiple strong indicators of potential fraud."

        # Highlight the top 2 most significant signals
        significant = sorted(
            [s for s in signals if s.score > 30],
            key=lambda s: s.score,
            reverse=True,
        )[:2]

        if significant:
            details = " Key concerns: " + "; ".join(s.description for s in significant)
            base += details

        return base

    # ================================================================== #
    #  Utility helpers
    # ================================================================== #

    def _normalize_domain(self, netloc: str) -> str:
        """Strip port and leading www. from a netloc string."""
        domain = netloc.lower().split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    def _coerce_datetime(self, value: object) -> Optional[datetime]:
        """Normalize WHOIS creation_date which can be list/str/datetime."""
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
