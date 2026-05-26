# SPECS.md — FraudGuard System Specifications

> **Version:** 1.0  
> **Date:** 2026-05-26  
> **System Vision:** A Chrome extension that analyzes the active website URL in real time to detect fraudulent and phishing banking or payment websites, using a multi-signal risk-scoring pipeline that triggers in-page warning overlays when risk scores exceed defined thresholds.

Each specification is tagged with a verifiability level:

- `[UNIT]` — verifiable via automated unit/API test
- `[INTEGRATION]` — verifiable by running the full stack (extension + backend)
- `[MANUAL]` — verifiable via manual browser observation

---

## Section 1 — System Scope & Goals

### SG-01 · Target Threat Class `[UNIT]`

The system MUST detect phishing and fraudulent websites that impersonate **banking or payment** institutions. Scope is limited to URL-based analysis; page content inspection is out of scope.

### SG-02 · URL as Primary Input `[UNIT]`

All fraud signals MUST be derived purely from the URL string and publicly available URL-metadata (WHOIS, SSL certificate, DNS). The system MUST NOT require reading page DOM content as a signal input.

### SG-03 · Real-Time Analysis `[INTEGRATION]`

The extension MUST trigger URL analysis within **3 seconds** of a page's `document_idle` event firing. For SPA navigation (URL change without full page reload), re-analysis MUST trigger within **2 seconds** of the URL change.

### SG-04 · In-Page Warning Overlay `[INTEGRATION]`

The system MUST render a visible warning element directly inside the active page when a risk score meets or exceeds the amber threshold (≥ 31). The overlay MUST NOT require the user to open the extension popup to see the warning.

### SG-05 · No False Silence on Backend Failure `[INTEGRATION]`

When the backend is unreachable, the extension MUST NOT silently classify the site as safe. It MUST surface a degraded-mode warning to the user.

---

## Section 2 — Backend API Contract

### API-01 · Health Endpoint `[UNIT]`

`GET /health` MUST return HTTP 200 with body `{ "status": "healthy" }` when the server is running.

### API-02 · Analyze Endpoint — Request Shape `[UNIT]`

`POST /analyze` MUST accept `Content-Type: application/json` with a body of:

```json
{ "url": "<valid HTTP or HTTPS URL>" }
```

The `url` field MUST be a valid HTTP or HTTPS URL. Malformed URLs (missing scheme, empty string, just a domain without scheme) MUST return HTTP 422.

### API-03 · Analyze Endpoint — Response Shape `[UNIT]`

A successful `POST /analyze` MUST return HTTP 200 with a JSON body containing all of the following fields:


| Field            | Type    | Constraint                                                         |
| ---------------- | ------- | ------------------------------------------------------------------ |
| `url`            | string  | The analyzed URL (trailing slash stripped)                         |
| `risk_score`     | float   | `0.0 ≤ risk_score ≤ 100.0`, rounded to 2 decimal places            |
| `risk_level`     | string  | One of: `"Safe"`, `"Suspicious"`, `"Dangerous"`                    |
| `signals`        | array   | Non-empty; each element has `name`, `score` (0–100), `description` |
| `explanation`    | string  | Non-empty human-readable explanation                               |
| `recommendation` | string  | Non-empty human-readable recommended action                        |
| `is_fallback`    | boolean | `false` for real analysis results                                  |


### API-04 · Analyze Endpoint — Error Handling `[UNIT]`

If the `analyze_url` function raises an unexpected exception, the endpoint MUST return HTTP 500 with a JSON body containing `{ "detail": "<error message>" }`. It MUST NOT return HTTP 200 with an error embedded in the result body.

### API-05 · CORS Policy `[UNIT]`

The backend MUST include `Access-Control-Allow-Origin: *` in all responses so that the Chrome extension's service worker (which has no origin) can reach the API.

### API-06 · Report Endpoint — Request Shape `[UNIT]`

`POST /report` MUST accept:

```json
{ "url": "<URL>", "reason": "<optional string>", "risk_score": "<optional float>" }
```

and return HTTP 200 with `{ "status": "received" }`.

---

## Section 3 — Risk Scoring System

### RS-01 · Score Range `[UNIT]`

The overall `risk_score` MUST always be a float in the range `[0.0, 100.0]` inclusive. No signal or weighted combination may produce a score outside this range.

### RS-02 · Risk Level Classification `[UNIT]`

Risk levels MUST be assigned by the following exclusive thresholds:


| Risk Level   | Score Range              |
| ------------ | ------------------------ |
| `Safe`       | 0.0 – 30.0 (inclusive)   |
| `Suspicious` | 30.1 – 70.0 (inclusive)  |
| `Dangerous`  | 70.1 – 100.0 (inclusive) |


### RS-03 · Signal Count `[UNIT]`

Every analysis response MUST contain **exactly 4 signals** (Phase 1) growing to **6 signals** after Phase 2 completion:


| Phase    | Signals Present                                        |
| -------- | ------------------------------------------------------ |
| Phase 1  | URL Similarity, Domain Age, SSL/HTTPS, Keyword Pattern |
| Phase 2+ | + URL Structure, + Safe Browsing                       |


### RS-04 · Signal Score Range `[UNIT]`

Every individual signal score MUST be a float in `[0.0, 100.0]`. A score of `0` means no risk detected for that signal. A score of `100` means maximum risk for that signal.

### RS-05 · Weighted Average Calculation `[UNIT]`

The overall `risk_score` MUST equal the weighted average of all signal scores. Weights MUST sum to exactly `1.0`.

**Phase 1 weights:**

```
URL Similarity  × 0.40
Domain Age      × 0.30
SSL/HTTPS       × 0.20
Keyword Pattern × 0.10
─────────────────────
Total             1.00
```

**Phase 2 weights (after adding URL Structure + Safe Browsing):**

```
URL Similarity  × 0.25
Domain Age      × 0.20
SSL/HTTPS       × 0.15
Keyword Pattern × 0.10
URL Structure   × 0.10
Safe Browsing   × 0.20
─────────────────────
Total             1.00
```

---

## Section 4 — Signal Specifications

### Signal S1 — URL Similarity

#### S1-01 · Exact Legitimate Domain Match `[UNIT]`

If the analyzed domain **exactly** matches any entry in `LEGITIMATE_DOMAINS` (after stripping `www.` prefix and port), the URL Similarity signal score MUST be `0.0`.

#### S1-02 · Typosquatting — Very High Similarity `[UNIT]`

If `SequenceMatcher.ratio()` between the analyzed domain and the closest legitimate domain is **> 0.85** (and the domain is not an exact match), the score MUST be:

```
score = min(100, ((ratio - 0.85) / 0.15) × 100)
```

Example: ratio `0.92` → score `46.7`.

#### S1-03 · Typosquatting — High Similarity `[UNIT]`

If ratio is in the range **(0.75, 0.85]**, score MUST be:

```
score = 50 + ((ratio - 0.75) / 0.10) × 50
```

#### S1-04 · Moderate Similarity with Financial Context `[UNIT]`

If ratio is in the range **(0.65, 0.75]** AND the domain contains a banking keyword (`bank`, `pay`, `secure`, `verify`, `chase`, `wells`, `citi`, `paypal`) OR contains a known-legitimate domain name as a substring, score MUST be in range `[30, 50]`.

#### S1-05 · Low Similarity `[UNIT]`

If ratio is **≤ 0.65**, score MUST be `0.0`.

#### S1-06 · Legitimate Domain List Coverage `[UNIT]`

`LEGITIMATE_DOMAINS` MUST contain at least **50 entries** covering:

- US banks (chase, bankofamerica, wellsfargo, citibank, usbank, pnc, capitalone, tdbank)
- Payment processors (paypal, stripe, square, venmo, zelle, cashapp, wise, revolut)
- Indian banks (icicibank, sbi, hdfcbank, axisbank, kotakbank)
- Global banks (hsbc, barclays, deutschebank, scotiabank, rbc)
- Digital payment (googlepay, phonepe, razorpay, paytm)

---

### Signal S2 — Domain Age

#### S2-01 · Very New Domain `[UNIT]`

Domain registered within the last **30 days**: score MUST be `90.0`.

#### S2-02 · New Domain `[UNIT]`

Domain registered between **30 and 180 days** ago: score MUST be `60.0`.

#### S2-03 · Seasoned Domain `[UNIT]`

Domain registered **more than 180 days** ago: score MUST be `0.0`.

#### S2-04 · WHOIS Failure — Neutral Score `[UNIT]`

When WHOIS lookup throws any exception (rate limit, unsupported TLD, network error), score MUST be `**15.0`** (neutral, not 90). The description MUST say "treated as neutral" and the score MUST match this description.

#### S2-05 · WHOIS Date Coercion `[UNIT]`

`_coerce_datetime()` MUST handle: `datetime` objects, ISO string `"YYYY-MM-DD"`, datetime string `"YYYY-MM-DDTHH:MM:SS"`, and a `list` whose first element is any of the above. It MUST return `None` for unsupported types.

---

### Signal S3 — SSL/HTTPS

#### S3-01 · HTTP URL (No HTTPS) `[UNIT]`

Any URL beginning with `http://` (not `https://`) MUST receive score `60.0` with description noting insecure transmission.

#### S3-02 · Valid SSL Certificate `[UNIT]`

HTTPS URL with a successfully validated certificate expiring **more than 30 days** from now: score MUST be `0.0`.

#### S3-03 · Expiring Certificate `[UNIT]`



HTTPS URL with a certificate expiring in **0–30 days**: score MUST be `50.0`.

#### S3-04 · Expired Certificate `[UNIT]`

HTTPS URL with an expired certificate (days_left < 0): score MUST be `90.0`.

#### S3-05 · SSL Check Failure — Neutral Score `[UNIT]`

When the SSL socket connection or certificate validation throws any exception, score MUST be `**15.0`** (neutral, not 90). The description MUST match the score value and not claim to be neutral while returning 90.

---

### Signal S4 — Keyword Pattern

#### S4-01 · No Keywords Found `[UNIT]`

URL containing none of the phishing keyword list: score MUST be `0.0`.

#### S4-02 · Keyword Score Calculation `[UNIT]`

Each matched keyword adds `20` points to the score, capped at `100.0`:

```
score = min(100, count_of_matched_keywords × 20)
```

#### S4-03 · Keyword List Coverage `[UNIT]`

The phishing keyword list MUST contain at least **20 patterns** including both hyphenated and non-hyphenated variants:

Hyphenated: `secure-login`, `verify-account`, `update-info`, `suspended-account`, `urgent-action`, `confirm-identity`, `security-alert`, `account-locked`, `verify-now`, `immediate-action`, `password-reset`, `billing-update`, `unusual-activity`, `confirm-payment`

Non-hyphenated: `securelogin`, `verifyaccount`, `updateinfo`

#### S4-04 · Case Insensitivity `[UNIT]`

Keyword matching MUST be case-insensitive. `VERIFY-ACCOUNT` in a URL MUST match the `verify-account` keyword.

---

### Signal S5 — URL Structure *(Phase 2)*

#### S5-01 · Suspicious TLD `[UNIT]`

If the domain's TLD is in the suspicious-TLD list, score MUST be at least `40.0`. Suspicious TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.buzz`, `.click`, `.link`.

#### S5-02 · IP Address as Domain `[UNIT]`

If the domain portion of the URL is a raw IPv4 or IPv6 address (e.g., `http://192.168.1.1/bank`), score MUST be `70.0`.

#### S5-03 · Excessive Subdomain Depth `[UNIT]`

If the hostname contains **3 or more subdomain levels** (e.g., `login.secure.evil.com` = 3 subdomains), the score MUST receive an addition of `+25` points (capped at 100 total).

#### S5-04 · Excessive URL Length `[UNIT]`

If the full URL length exceeds **120 characters**, score MUST receive a `+15` addition (capped at 100 total).

#### S5-05 · Clean URL `[UNIT]`

URL with a standard TLD, no IP, ≤ 2 subdomain levels, and length ≤ 120 chars: score MUST be `0.0`.

---

### Signal S6 — Safe Browsing *(Phase 2)*

#### S6-01 · Blocklist Hit `[UNIT]`

If the Google Safe Browsing API returns a threat match for the URL, score MUST be `100.0` and risk level MUST be `"Dangerous"` regardless of other signal scores.

#### S6-02 · Clean URL `[UNIT]`

If Safe Browsing API returns no threats for the URL, score MUST be `0.0`.

#### S6-03 · API Key Not Configured — Graceful Fallback `[UNIT]`

If `SAFE_BROWSING_API_KEY` is not set in config/environment, the signal MUST return score `0.0` and description `"Safe Browsing not configured; signal skipped"`. The system MUST NOT crash or error.

#### S6-04 · API Failure — Neutral Fallback `[UNIT]`

If the Safe Browsing API call fails (network error, quota exceeded), score MUST be `0.0` with description noting the failure. The system MUST NOT raise an unhandled exception.

---

## Section 5 — Overlay & UX Behavior

### OV-01 · Tier 1 Warning — Amber Banner `[INTEGRATION]`

When `risk_score ≥ 31` AND `risk_score < 50`, the content script MUST inject a **non-blocking amber banner** at the top of the page. The banner MUST:

- Span the full page width
- Display the risk level, score, and a brief explanation
- Include a dismiss button that removes it permanently for that page load
- Not block page interaction (not a modal overlay)

### OV-02 · Tier 2 Warning — Full Overlay `[INTEGRATION]`

When `risk_score ≥ 50`, the content script MUST inject a **blocking modal overlay** over the page. The overlay MUST:

- Cover the entire viewport (position: fixed; z-index: 999999)
- Display: risk badge (color-coded), risk score out of 100, explanation text, detected signal descriptions, recommendation
- Present three action buttons: **Exit Site**, **Report Fraud**, **Continue Anyway**
- Animate in smoothly (CSS transition)

### OV-03 · Safe Sites — No Overlay `[INTEGRATION]`

When `risk_score < 31`, no overlay or banner element MUST exist in the page DOM. If a previous overlay exists from a prior URL, it MUST be removed.

### OV-04 · Exit Site Button `[INTEGRATION]`

Clicking **Exit Site** MUST navigate the current tab to `about:blank` and remove the overlay.

### OV-05 · Continue Anyway Button `[INTEGRATION]`

Clicking **Continue Anyway** MUST remove the overlay and MUST store an acknowledgment in `localStorage` keyed by the URL so the overlay does not re-appear for that URL during the same session.

### OV-06 · Report Fraud Button `[INTEGRATION]`

Clicking **Report Fraud** MUST submit a report to `POST /report` on the backend with the current URL and risk score. On success, the overlay MUST close and a brief confirmation MUST be shown (NOT a blocking `alert()`).

### OV-07 · Overlay Does Not Re-Inject `[INTEGRATION]`

If the user has already been shown the overlay for the current URL and clicked **Continue Anyway**, revisiting the same URL within the same browser session MUST NOT re-show the overlay.

### OV-08 · SPA Navigation Re-Analysis `[INTEGRATION]`

When the page URL changes without a full page reload (SPA navigation), the content script MUST detect the URL change within **1 second** and trigger a fresh analysis of the new URL.

### OV-09 · Risk Badge Color Coding `[MANUAL]`

Overlay risk badges MUST use distinct colors:


| Risk Level | Badge Color        |
| ---------- | ------------------ |
| Safe       | Green (`#4caf50`)  |
| Suspicious | Orange (`#ff9800`) |
| Dangerous  | Red (`#f44336`)    |


---

## Section 6 — Toolbar Badge

### TB-01 · Badge Update on Analysis `[INTEGRATION]`

After every URL analysis completes, `chrome.action.setBadgeText()` MUST be called on the active tab with a value reflecting the score.

### TB-02 · Badge Text Format `[MANUAL]`

Badge text MUST display a 1–3 character indicator:


| Risk Level         | Badge Text                      |
| ------------------ | ------------------------------- |
| Safe (0–30)        | `✓` or empty                    |
| Suspicious (31–70) | score as integer (e.g., `"45"`) |
| Dangerous (70+)    | score as integer (e.g., `"85"`) |


### TB-03 · Badge Color `[MANUAL]`

Badge background color MUST match the risk level:


| Risk Level                 | Badge Background                   |
| -------------------------- | ---------------------------------- |
| Safe                       | `#4caf50` (green)                  |
| Suspicious                 | `#ff9800` (orange)                 |
| Dangerous                  | `#f44336` (red)                    |
| Backend offline / fallback | `#ffeb3b` (yellow) with text `"!"` |


### TB-04 · Badge Clears on Chrome/Extension Pages `[INTEGRATION]`

On `chrome://`, `chrome-extension://`, or other non-analyzable pages, the badge MUST be cleared (empty text).

---

## Section 7 — Extension Messaging & Lifecycle

### EX-01 · Content Script Injection `[INTEGRATION]`

`content.js` and `styles.css` MUST be injected on all `http://` and `https://` URLs at `document_idle`. They MUST NOT be injected on `chrome://`, `about:`, or `chrome-extension://` URLs.

### EX-02 · Message Protocol — Analyze `[UNIT]`

The content script MUST send `{ action: 'analyze', url: <string> }` to the background service worker. The background MUST respond with `{ success: true, data: <AnalyzeResponse> }` on success, or `{ success: false, error: <string> }` on failure.

### EX-03 · No Duplicate Analysis for Same URL `[UNIT]`

If the content script calls `analyzeCurrentUrl()` while the URL has not changed from the last analyzed URL (`currentUrl` module variable), it MUST return early without sending a new message. This prevents redundant backend calls on scroll events or focus changes.

### EX-04 · Variable Scope Correctness `[UNIT]`

There MUST be no variable shadowing between the module-level `currentUrl` tracking variable and the local URL variable used inside the `setInterval` URL-change poll. The setInterval's local variable MUST be named distinctly (e.g., `lastUrl`).

### EX-05 · Backend URL Configuration `[UNIT]`

The backend URL (`BACKEND_URL`) MUST be defined in exactly one place in `background.js` as a top-level constant. It MUST NOT be repeated inline in multiple fetch calls.

---

## Section 8 — Error Handling & Degraded Mode

### ER-01 · Backend Unreachable — No Silent Safe `[INTEGRATION]`

When `fetch()` to `/analyze` fails with any network error (connection refused, timeout, DNS failure), the response returned to the content script MUST have:

- `risk_score`: `70.0`  
- `risk_level`: `"Suspicious"`  
- `is_fallback`: `true`  
- `explanation`: a non-empty string indicating the backend is unavailable

### ER-02 · Backend Unreachable — Overlay Fires `[INTEGRATION]`

Given ER-01, because `risk_score = 70` meets the Tier 2 threshold (≥ 50), the full overlay MUST appear on every site when the backend is down. The overlay MUST clearly indicate "verification unavailable" not "this site is dangerous."

### ER-03 · HTTP Error Response `[UNIT]`

If the backend returns a non-2xx HTTP status, the background MUST throw an error that is caught by the catch block, triggering the degraded-mode response (ER-01). It MUST NOT attempt to parse the error response body as an `AnalyzeResponse`.

### ER-04 · Content Script Message Error `[UNIT]`

If `chrome.runtime.lastError` is set after `sendMessage()`, the content script MUST log the error and MUST NOT attempt to call `handleAnalysisResult()` with undefined/null data.

### ER-05 · Invalid URL from Content Script `[UNIT]`

If the URL passed by the content script is not a valid HTTP/HTTPS URL (e.g., `about:blank`, `chrome://newtab`), the background MUST return `{ success: false, error: "invalid URL" }` without calling the backend.

---

## Section 9 — Caching

### CA-01 · Cache Hit Avoids Backend Call `[UNIT]`

If a URL has been analyzed and the result is cached, a subsequent analysis request for the same URL MUST return the cached result immediately without making any network call to the backend.

### CA-02 · Cache Storage — Persistent `[INTEGRATION]`

The analysis cache MUST be stored in `chrome.storage.local`, not in an in-memory `Map`. Cached results MUST survive MV3 service worker restarts.

### CA-03 · Cache TTL `[UNIT]`

Each cached entry MUST have a timestamp. Entries older than **60 minutes** MUST be treated as expired and a fresh backend call MUST be made. Expired entries MUST be removed from storage.

### CA-04 · Cache Invalidation on Navigation `[INTEGRATION]`

When `chrome.tabs.onUpdated` fires with `changeInfo.status === 'loading'` for a tab, the cached result for the previous URL of that tab MUST be invalidated.

### CA-05 · Fallback Results Not Cached `[UNIT]`

Results with `is_fallback: true` (backend unreachable) MUST NOT be cached. Every page load MUST retry the backend when the server recovers.

---

## Section 10 — Code Quality & Debug Hygiene

### CQ-01 · No Debug Telemetry in Production `[UNIT]`

The codebase MUST contain no `fetch()` calls to `127.0.0.1:7243` or any hardcoded external telemetry/debug endpoint. All `#region agent log` / `#endregion` blocks MUST be removed.

### CQ-02 · No Hardcoded Filesystem Paths `[UNIT]`

`main.py` MUST NOT contain any hardcoded absolute filesystem paths (e.g., `/Users/ayushpetwal/Desktop/FR_2/...`). All file I/O for logging MUST use Python's `logging` module with configurable handlers, not direct `open()` calls.

### CQ-03 · Logging via Standard Libraries `[UNIT]`

Backend logging MUST use Python's `logging` module. Extension logging MUST use `console.log` / `console.error` / `console.warn`. Neither system may use `print()` (Python) or bare `alert()` (JS) for operational logging.

### CQ-04 · Dead Code Removal `[UNIT]`

The `getAnalysis` message handler in `background.js` (which is never called by any extension file) MUST either be wired up and documented or removed entirely.

---

## Section 11 — Performance

### PF-01 · Analysis Response Time `[INTEGRATION]`

The `/analyze` endpoint MUST respond within **8 seconds** for any URL under normal network conditions (WHOIS + SSL lookups are the bottleneck). The backend MUST use `asyncio` timeouts or background threads for external IO to avoid blocking the event loop.

### PF-02 · Async External Lookups `[UNIT]`

WHOIS and SSL checks MUST run with socket-level timeouts. The `socket.create_connection()` call in `_check_ssl` MUST have a timeout of ≤ 5 seconds. WHOIS lookups MUST complete or fail within 5 seconds.

### PF-03 · Content Script Poll Interval `[UNIT]`

The SPA URL-change detection poll in `content.js` MUST run no more frequently than **once per second** (`setInterval(..., 1000)`).

### PF-04 · No Redundant Badge Updates `[UNIT]`

Badge text and color MUST only be updated if the new value differs from the currently displayed value. Redundant `setBadgeText` calls on every poll tick are prohibited.

---

## Section 12 — Security

### SEC-01 · API Key Not Exposed to Extension `[UNIT]`

The Google Safe Browsing API key MUST reside only in the backend's `.env` / config. It MUST NOT appear in any extension file (`background.js`, `content.js`, `popup.js`, `manifest.json`).

### SEC-02 · No User Data Exfiltration `[MANUAL]`

The extension MUST NOT send page content, cookies, form field values, or user-typed input to any external endpoint. Only the current tab's URL MUST be sent to the backend.

### SEC-03 · Report Endpoint — Input Validation `[UNIT]`

`POST /report` MUST validate that `url` is a valid HTTP/HTTPS URL (Pydantic `HttpUrl`). Arbitrary strings, SQL-injectable values, or non-URL inputs MUST return HTTP 422.

### SEC-04 · CORS Must Not Accept Credentials on Wildcard `[UNIT]`

The backend MUST NOT set both `allow_origins=["*"]` and `allow_credentials=True` simultaneously (this is a CORS security misconfiguration). Since the extension service worker sends no cookies, `allow_credentials` MUST be `False`.

### SEC-05 · XSS Prevention in Injected Overlay `[UNIT]`

The overlay HTML constructed in `injectWarningPopup()` MUST NOT use `innerHTML` to interpolate untrusted URL strings directly. Any URL displayed in the overlay MUST be set via `textContent` or be properly escaped before being passed to `innerHTML`.

---

## Section 13 — Verification Checklist

The following scenarios collectively verify all system goals. All MUST pass for the system to be considered complete.

### Core Popup Functionality


| #    | Scenario                         | Input                                             | Expected Result                                                                           | Spec Refs           |
| ---- | -------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------- |
| V-01 | Backend offline — no silent safe | Backend stopped, visit any HTTPS site             | Tier 2 overlay with "backend unavailable" text                                            | ER-01, ER-02, OV-02 |
| V-02 | Exact legitimate domain          | `https://chase.com`                               | Score ≈ 0, `Safe`, no overlay                                                             | S1-01, OV-03        |
| V-03 | Typosquatting                    | `https://chas3.com`                               | Score ≥ 40, overlay fires                                                                 | S1-02, OV-01/02     |
| V-04 | Phishing keywords in URL         | `https://example.com/secure-login/verify-account` | Score ≥ 40 (keywords contribute ≥ 40 × 0.10 = 4 pts), overlay fires if other signals high | S4-01, S4-02        |
| V-05 | Safe legitimate site             | `https://paypal.com`                              | Score = 0, `Safe`, no overlay                                                             | S1-01, OV-03        |
| V-06 | WHOIS lookup fails               | Mock WHOIS exception for any domain               | Domain Age signal score = 15, not 90                                                      | S2-04               |
| V-07 | SSL check fails                  | Mock SSL exception for HTTPS site                 | SSL signal score = 15, not 90                                                             | S3-05               |


### Tier Classification


| #    | Scenario     | Expected Overlay Type                  | Spec Ref     |
| ---- | ------------ | -------------------------------------- | ------------ |
| V-08 | Score 0–30   | No overlay                             | OV-03        |
| V-09 | Score 31–49  | Amber banner (non-blocking)            | OV-01        |
| V-10 | Score 50–70  | Full blocking overlay                  | OV-02        |
| V-11 | Score 71–100 | Full blocking overlay, Dangerous badge | OV-02, OV-09 |


### URL Structure Signal *(Phase 2)*


| #    | Scenario            | Expected Score             | Spec Ref |
| ---- | ------------------- | -------------------------- | -------- |
| V-12 | Domain `.tk` TLD    | URL Structure ≥ 40         | S5-01    |
| V-13 | IP address URL      | URL Structure = 70         | S5-02    |
| V-14 | 3+ subdomain levels | URL Structure receives +25 | S5-03    |
| V-15 | URL > 120 chars     | URL Structure receives +15 | S5-04    |
| V-16 | Clean standard URL  | URL Structure = 0          | S5-05    |


### Extension Behavior


| #    | Scenario                  | Expected Behavior                                     | Spec Ref            |
| ---- | ------------------------- | ----------------------------------------------------- | ------------------- |
| V-17 | Same URL, no change       | No second backend call made                           | EX-03               |
| V-18 | SPA navigation            | Re-analysis within 2 seconds                          | SG-03, OV-08        |
| V-19 | Badge after analysis      | Score and color appear on icon                        | TB-01, TB-02, TB-03 |
| V-20 | Backend comes back online | Next page load shows real result, not cached fallback | CA-05               |
| V-21 | Revisit acknowledged URL  | Overlay does NOT re-appear                            | OV-07               |


### Code Quality


| #    | Check                                       | Expected Result                                 | Spec Ref |
| ---- | ------------------------------------------- | ----------------------------------------------- | -------- |
| V-22 | Grep for `127.0.0.1:7243`                   | Zero results in any extension or server file    | CQ-01    |
| V-23 | Grep for `FR_2` or hardcoded `/Users/` path | Zero results in `main.py`                       | CQ-02    |
| V-24 | Grep for `risk_score: 0` in catch block     | Zero results — fallback must not return score 0 | ER-01    |


---

## Section 14 — Configuration Reference

All configurable values and their required defaults:


| Config Key              | Location                 | Default                 | Description                             |
| ----------------------- | ------------------------ | ----------------------- | --------------------------------------- |
| `BACKEND_URL`           | `background.js` constant | `http://localhost:8000` | Backend API base URL                    |
| `safe_threshold`        | `config.py` / `.env`     | `30`                    | Max score for Safe classification       |
| `suspicious_threshold`  | `config.py` / `.env`     | `70`                    | Max score for Suspicious classification |
| `AMBER_THRESHOLD`       | `content.js` constant    | `31`                    | Min score for Tier 1 amber banner       |
| `OVERLAY_THRESHOLD`     | `content.js` constant    | `50`                    | Min score for Tier 2 blocking overlay   |
| `CACHE_TTL_MINUTES`     | `background.js` constant | `60`                    | Minutes before a cached result expires  |
| `SAFE_BROWSING_API_KEY` | `.env` only              | `""` (optional)         | Google Safe Browsing API key            |
| `cors_origins`          | `config.py`              | `["*"]`                 | Allowed CORS origins                    |
| `WHOIS_TIMEOUT_SECS`    | `fraud_detector.py`      | `5`                     | Max seconds for WHOIS lookup            |
| `SSL_TIMEOUT_SECS`      | `fraud_detector.py`      | `5`                     | Max seconds for SSL socket connection   |


