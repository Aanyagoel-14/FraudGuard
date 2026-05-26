# PLAN v1 — FraudGuard: Root Cause Analysis & Fix Plan

> **Date:** 2026-05-26  
> **Problem:** Extension popup doesn't appear on malicious sites  
> **Scope:** Full system audit + prioritized fix plan  
>  
> **Original Vision:**  
> - Chrome extension that analyzes the active website **URL** in real time to detect fraudulent/phishing **banking or payment** websites  
> - Risk-scoring pipeline evaluating **4+ signals**: URL similarity, domain age, HTTPS validation, phishing indicators  
> - **In-page warning overlays** that trigger when risk scores exceed predefined thresholds

---

## 1. System Architecture (As-Is)

```
┌─────────────────────┐     chrome.runtime      ┌─────────────────────┐
│    content.js        │ ─── sendMessage ──────► │   background.js     │
│  (injected on every  │ ◄── response ────────── │  (service worker)   │
│   page at doc_idle)  │                         │                     │
│                      │                         │  fetch() POST       │
│  • monitors URL      │                         │  /analyze           │
│  • injects popup DOM │                         │      │              │
│    if score ≥ 40     │                         │      ▼              │
└─────────────────────┘                         └──────┬──────────────┘
                                                        │
                                                   HTTP │ localhost:8000
                                                        │
                                                ┌───────▼──────────────┐
                                                │  FastAPI Backend      │
                                                │  server/main.py      │
                                                │                      │
                                                │  POST /analyze       │
                                                │    → FraudDetector   │
                                                │      4 signals:      │
                                                │      1. URL Similarity│
                                                │      2. Domain Age   │
                                                │      3. SSL/HTTPS    │
                                                │      4. Keyword Scan │
                                                └──────────────────────┘
```

**Signal weights:** URL Similarity (0.4) · Domain Age (0.3) · SSL/HTTPS (0.2) · Keywords (0.1)  
**Thresholds:** Safe ≤ 30 · Suspicious 31–70 · Dangerous > 70  
**Popup trigger:** content.js fires at `risk_score ≥ 40`

---

## 2. Root Cause Analysis

### 🔴 Critical Bug #1 — Backend-Down Silent Failure

**The most likely single cause of the reported issue.**

| | |
|---|---|
| **File** | `extension/background.js` lines 78–93 |
| **What happens** | When `fetch('http://localhost:8000/analyze')` fails (server not running), the catch block returns `{ risk_score: 0, risk_level: 'Safe' }` |
| **Impact** | Content script sees score 0 < 40 → **no popup on ANY site, ever** |
| **User sees** | Absolutely nothing — no error, no badge, no warning |

```javascript
// background.js:85-93 — the silent killer
catch (error) {
    return {
        risk_score: 0,        // ← tells content.js "all clear"
        risk_level: 'Safe',   // ← lies to the user
        signals: [],
        explanation: 'Unable to analyze URL. Please check backend connection.',
        recommendation: 'Proceed with caution.',
        error: error.message
    };
}
```

### 🔴 Critical Bug #2 — WHOIS/SSL Failure Scores: Code Says 90, Comment Says "Neutral"

| | |
|---|---|
| **File** | `server/fraud_detector.py` lines 218 and 263 |
| **What happens** | When WHOIS lookup or SSL validation throws an exception, score is set to `90.0` — but the description string says "treated as neutral for risk scoring" |
| **Impact** | WHOIS/SSL lookups fail frequently (rate limits, firewalls). A legitimate site like `google.com` with both failures scores: `(0×0.4) + (90×0.3) + (90×0.2) + (0×0.1) = 45` → **false positive popup on safe sites** |
| **Secondary impact** | These false positives likely caused the popup threshold to be raised from 30 to 40, which then lets some malicious sites slip under the radar |

```python
# fraud_detector.py:215-219 — says neutral, does maximum risk
except Exception as exc:
    score = 90.0  # ← THIS IS NOT NEUTRAL. This is maximum risk.
    description = f"Could not verify domain age ({exc}); treated as neutral for risk scoring"
    #                                                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #                                                       The description LIES about the score
```

### 🔴 Critical Bug #3 — Detection Algorithm Has Fundamental Gaps

| Gap | Impact |
|-----|--------|
| Only **16 hardcoded legitimate domains** | Phishing sites targeting banks outside this list get URL Similarity = 0 (the highest-weighted signal at 40%) |
| Only **10 hyphenated keyword phrases** | Trivially evadable — `securelogin` (no hyphen) bypasses `secure-login` check |
| **No external threat intelligence** | No Google Safe Browsing, PhishTank, VirusTotal — purely heuristic |
| **No suspicious TLD scoring** | Free-abuse TLDs like `.tk`, `.ml`, `.xyz` are not treated as a URL signal |

**Example failure:** A phishing site at `https://mybank-secure.com/login` targeting a bank not in the 16-domain list:
- URL Similarity: ~0 (no close match to the 16 domains)
- Domain Age: 0 if old domain, 90 if WHOIS fails  
- SSL: 0 if valid cert  
- Keywords: 0 (no matching hyphenated phrases)
- TLD: not scored at all
- **Total: 0 to 27 → well below 40 → no popup**

Note: This is a URL-analysis gap — the system doesn't extract enough signal from the URL itself (TLD, subdomain depth, path patterns, URL entropy).

---

## 3. Moderate Issues

| # | Issue | Location | Impact |
|---|-------|----------|--------|
| M1 | **Popup threshold gap:** Scores 31–39 are "Suspicious" per backend but content.js only shows popup at ≥ 40 | `content.js:61` | Some suspicious sites get no warning |
| M2 | **Empty `tabs.onUpdated` handler:** Background never proactively analyzes — all depends on content script injection | `background.js:128-133` | No fallback if content script fails |
| M3 | **Variable shadowing:** `const currentUrl` in setInterval shadows module-level `let currentUrl` | `content.js:186` | Fragile code |
| M4 | **Debug logging cruft:** Posts to `127.0.0.1:7243`, writes to wrong path (`FR_2/FraudGuard/`) | `background.js`, `main.py` | Dead code, wrong paths, unnecessary fetches |
| M5 | **No toolbar badge:** Icon never updates — users can't see risk level at a glance | Missing entirely | Zero passive safety indication |

---

## 4. Missing Fundamental Pieces

| # | What's Missing | Why It Matters | Fits URL-Analysis Vision? |
|---|---------------|----------------|---------------------------|
| F1 | External URL threat intelligence (Safe Browsing / PhishTank) | Heuristics alone cannot reliably detect phishing — industry uses URL blocklists as primary signal | Yes — URL lookup |
| F2 | Suspicious TLD scoring | Free-abuse TLDs (`.tk`, `.ml`, `.xyz`, `.top`, `.buzz`) are strong phishing indicators not scored | Yes — URL signal |
| F3 | URL structural analysis | Subdomain depth, path length, URL entropy, IP-address-as-domain are all URL-derived signals | Yes — URL signal |
| F4 | Error/degraded state UI | When backend is down, user sees nothing — should see "unverified" warning | N/A — UX |
| F5 | Persistent cache (chrome.storage) | In-memory Map clears on every service worker restart — results lost constantly in MV3 | N/A — reliability |
| F6 | Fraud reporting mechanism | "Report Fraud" button is a `TODO` stub — `alert('Thank you')` with no actual reporting | N/A — UX |
| F7 | Proper extension icons | All three icon PNGs are 1×1 pixel placeholders | N/A — cosmetic |

---

## 5. Fix Plan — Prioritized Phases

### Phase 1: Fix the Popup (Core Bug Fixes) 🔥

> **Goal:** Make the popup reliably appear when it should, and stop appearing when it shouldn't.

#### 1A. Fix backend-failure fallback (`background.js`)

**Current:** Returns `risk_score: 0, risk_level: 'Safe'` on fetch failure  
**Fix:** Return a high-caution response with a distinct `is_fallback` flag

```javascript
// NEW catch block
return {
    url: url,
    risk_score: 70,
    risk_level: 'Suspicious',
    signals: [],
    explanation: '⚠️ Could not verify this site — backend unavailable. Proceed with caution.',
    recommendation: 'The fraud detection server is not reachable. Be cautious with any sensitive information.',
    is_fallback: true,
    error: error.message
};
```

#### 1B. Fix WHOIS/SSL failure scores (`fraud_detector.py`)

**Current:** `score = 90.0` on exception  
**Fix:** `score = 15.0` (genuinely neutral — slight caution without overwhelming the weighted average)

```python
# _check_domain_age exception handler (line 218)
score = 15.0
description = f"Could not verify domain age ({exc}); treated as neutral"

# _check_ssl exception handler (line 263)  
score = 15.0
description = f"Could not validate SSL certificate ({exc}); treated as neutral"
```

**Math check with new scores:**
- Legitimate site (google.com), both fail: `(0×0.4) + (15×0.3) + (15×0.2) + (0×0.1) = 7.5` → **Safe** ✅
- Typosquatting site (chas3.com), both fail: `(85×0.4) + (15×0.3) + (15×0.2) + (0×0.1) = 41.5` → **Popup shows** ✅
- New domain + no HTTPS + keywords: `(0×0.4) + (90×0.3) + (60×0.2) + (40×0.1) = 43` → **Popup shows** ✅

#### 1C. Align popup threshold with backend classification (`content.js`)

**Current:** Popup at `risk_score >= 40` but backend says "Suspicious" starts at 31  
**Fix:** Two-tier warning system:
- Score 31–49: **Amber banner** at top of page (non-blocking, dismissible)
- Score ≥ 50: **Full overlay popup** (blocking, requires user action)

---

### Phase 2: Strengthen the URL-Analysis Pipeline 🛡️

> **Goal:** Make the URL-based detector actually catch malicious banking/payment sites reliably.  
> **Constraint:** All new signals must be derived purely from the URL — consistent with the original vision.

#### 2A. Expand legitimate domains list — focus on banking/payment

Add 30–40 more **banking and payment** domains (do NOT expand to generic tech targets):
- **Indian banks:** icicibank.com, sbi.co.in, hdfcbank.com, axisbank.com, kotakbank.com, yesbank.in
- **Global banks:** hsbc.com, barclays.co.uk, deutschebank.com, bnpparibas.com, scotiabank.com, rbc.com
- **Digital payment:** cashapp.com, googlepay.com, phonepe.com, razorpay.com, paytm.com, wise.com, revolut.com

Tech giants (Google, Apple, Amazon) are out of scope per the banking/payment focus.

#### 2B. Expand keyword & phishing indicator detection

- Add non-hyphenated variants to keyword list: `securelogin`, `verifyaccount`, `updateinfo`
- Add new financial-context patterns: `account-locked`, `password-reset`, `billing-update`, `unusual-activity`, `confirm-payment`
- Add subdomain-based signals: if URL has 3+ subdomain levels (e.g., `login.secure.chas3.tk`) that is a strong phishing indicator

#### 2C. Add URL structural signal (new 5th signal — URL-native)

A standalone `_check_url_structure` method in `FraudDetector`, weight 0.10 (redistribute weights proportionally):
- **Suspicious TLD:** `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.buzz` → +30–50 points
- **Excessive subdomain depth:** 3+ levels → +20 points  
- **IP address as domain:** e.g., `192.168.1.1/bank` → +60 points
- **Long random-looking path:** URL length > 120 chars → +15 points
- **New weights:** Similarity 0.35 · Domain Age 0.25 · SSL 0.20 · Keywords 0.10 · URL Structure 0.10

#### 2D. Integrate Google Safe Browsing API (new 6th signal — URL lookup)

This is still URL-analysis — it looks up the URL against Google's threat database, not the page content:
- Free tier: 10,000 lookups/day
- Weight: 0.25 (as a high-confidence authoritative signal)
- Blocklist match → score 100 (definitive)
- **Final weights:** Similarity 0.25 · Domain Age 0.20 · SSL 0.15 · Keywords 0.10 · URL Structure 0.10 · Safe Browsing 0.20
- Safe Browsing key stored in `config.py` / `.env`, graceful fallback (score 0) if key not configured

---

### Phase 3: Fix Moderate Issues & UX 🔧

> **Goal:** Clean up code, add visual indicators, improve reliability.

| Task | What to do |
|------|-----------|
| **3A. Clean debug cruft** | Remove all `#region agent log` blocks from `background.js` and `main.py`. Remove hardcoded `FR_2/` path. Use proper `console.log` / Python `logging`. |
| **3B. Add toolbar badge** | Use `chrome.action.setBadgeText()` + `setBadgeBackgroundColor()` after each analysis. Show score number with color (green/orange/red). Show "!" on backend failure. |
| **3C. Fix variable shadowing** | Rename `const currentUrl` at `content.js:186` to `const newUrl`. |
| **3D. Implement tabs.onUpdated** | Clear cache for tab URL on navigation. Optionally re-trigger content script analysis. |
| **3E. Add persistent cache** | Replace in-memory `Map` with `chrome.storage.local`. Add 1-hour TTL per entry. Survives MV3 service worker restarts. |

---

### Phase 4: Polish ✨

| Task | What to do |
|------|-----------|
| **4A. Proper icons** | Generate 16×16, 48×48, 128×128 shield-style icons |
| **4B. Fraud reporting** | Add `/report` endpoint. Replace `alert()` stub with actual API call |
| **4C. Connection indicator** | Show backend online/offline status in toolbar popup |

---

## 6. Critical Files to Modify

| File | Changes |
|------|---------|
| `extension/background.js` | Fix catch block (1A), add badge logic (3B), implement tabs.onUpdated (3D), persistent cache (3E), clean debug (3A) |
| `extension/content.js` | Two-tier warning system (1C), fix variable shadowing (3C) |
| `server/fraud_detector.py` | Fix WHOIS/SSL scores (1B), expand banking/payment domains (2A), expand keywords (2B), add URL structure signal (2C), add Safe Browsing signal (2D) |
| `server/main.py` | Clean debug cruft (3A), add `/report` endpoint (4B) |
| `server/models.py` | Add `is_fallback` field to response (1A) |
| `server/config.py` | Add Safe Browsing API key config (2D) |
| `extension/popup.html` / `popup.js` | Connection status indicator (4C) |
| `extension/styles.css` | Amber banner styles for tier-2 warning (1C) |
| `extension/manifest.json` | No new permissions needed (badge uses existing `action` API) |

---

## 7. Verification Plan

| Test | Expected Result |
|------|----------------|
| Start extension **without** backend running → visit any site | Should see "backend unavailable" warning with score ~70 |
| Start backend → visit `https://chase.com` | Score near 0, **no popup** (exact legitimate domain match) |
| Visit `https://chas3.com` (typosquatting) | High similarity score → **popup appears** |
| Visit `https://random-unknown-site.tk/secure-login/verify` | Keywords + suspicious TLD → **popup appears** |
| Visit `https://google.com`, `https://github.com`, `https://youtube.com` | All score < 30, **no popup** (no false positives) |
| Navigate between sites | Toolbar badge updates with score + color on each navigation |
| Click "Report Fraud" on popup | Sends report to backend (not just an alert) |
| Kill backend mid-session → navigate to new site | Badge shows "!" warning, page shows degraded-mode warning |

---

## 8. Execution Priority

```
PHASE 1 (Critical — fixes the reported bug, ~2-3 hrs)
  1A: Fix backend-failure fallback in background.js
  1B: Fix WHOIS/SSL scores from 90 → 15 in fraud_detector.py
  1C: Two-tier overlay threshold in content.js
  → Test: popup now fires on typosquatting URLs

PHASE 2 (High — strengthens URL-based detection, ~4-5 hrs)
  2A: Expand banking/payment domains list
  2B: Expand keywords + add subdomain depth signal
  2C: Add URL structure signal (new 5th signal — TLD, depth, IP, length)
  2D: Google Safe Browsing API integration (new 6th signal — URL lookup)
  → Test: catches .tk domains, deep subdomain phishing, blocklisted URLs

PHASE 3 (Medium — code quality & UX, ~2-3 hrs)
  3A: Remove all debug cruft from background.js and main.py
  3B: Add toolbar badge (score + color) 
  3C: Fix variable shadowing in content.js
  3D: Implement tabs.onUpdated for real-time navigation handling
  3E: Persistent cache with chrome.storage.local
  → Test: badge updates on navigation, no false debug traffic

PHASE 4 (Low — polish, ~1-2 hrs)
  4A: Generate proper extension icons
  4B: Wire up fraud reporting to backend /report endpoint
  4C: Add connection status in popup
```

**Alignment with original vision:**
- Phase 1 restores the core thesis: URL → pipeline → overlay
- Phase 2 deepens the pipeline with URL-native signals only (no DOM/content analysis)  
- Phase 2D (Safe Browsing) is still URL-lookup — consistent with "analyzes the active website URL"
- Domain focus stays on banking/payment, not general phishing
- The overlay system is preserved and improved (two tiers instead of one)
