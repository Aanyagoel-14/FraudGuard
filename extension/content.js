/**
 * FraudGuard — Content Script
 *
 * Monitors the active page URL in real time and injects a warning UI when
 * the FraudGuard risk score meets or exceeds a threshold.
 *
 * Two-tier warning system (per SPECS §5):
 *   Score 31–49  →  Amber banner  (non-blocking, top of page, dismissible)
 *   Score ≥ 50   →  Full overlay  (blocking modal, requires user action)
 *   Score < 31   →  No UI         (remove any existing warning)
 */

// ------------------------------------------------------------------ //
//  Constants
// ------------------------------------------------------------------ //

const AMBER_THRESHOLD   = 31;   // Minimum score for Tier-1 amber banner
const OVERLAY_THRESHOLD = 50;   // Minimum score for Tier-2 blocking overlay

// ------------------------------------------------------------------ //
//  Module state
// ------------------------------------------------------------------ //

/** URL of the last page that was submitted for analysis. */
let currentUrl = null;

// ------------------------------------------------------------------ //
//  URL utilities
// ------------------------------------------------------------------ //

function getCurrentUrl() {
  return window.location.href;
}

// ------------------------------------------------------------------ //
//  Core analysis trigger
// ------------------------------------------------------------------ //

/**
 * Send the current page URL to the background worker for analysis.
 * Skips if the URL has not changed since the last call.
 */
async function analyzeCurrentUrl() {
  const url = getCurrentUrl();

  if (url === currentUrl) return;   // de-duplicate: same URL as last check
  currentUrl = url;

  // Skip non-HTTP pages (chrome://, about:, file://, etc.)
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    removeAllWarnings();
    return;
  }

  console.log('[FraudGuard] Analyzing:', url);

  chrome.runtime.sendMessage({ action: 'analyze', url }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('[FraudGuard] Message error:', chrome.runtime.lastError.message);
      return;
    }
    if (response?.success) {
      handleAnalysisResult(response.data);
    } else {
      console.error('[FraudGuard] Analysis failed:', response?.error);
    }
  });
}

// ------------------------------------------------------------------ //
//  Result handler — two-tier dispatch
// ------------------------------------------------------------------ //

/**
 * Route an AnalyzeResponse to the correct warning tier.
 */
function handleAnalysisResult(analysis) {
  const score = analysis.risk_score ?? 0;

  if (score >= OVERLAY_THRESHOLD) {
    removeAmberBanner();
    injectOverlay(analysis);
  } else if (score >= AMBER_THRESHOLD) {
    removeOverlay();
    injectAmberBanner(analysis);
  } else {
    removeAllWarnings();
  }
}

// ------------------------------------------------------------------ //
//  Tier 1 — Amber banner  (non-blocking, score 31-49)
// ------------------------------------------------------------------ //

function injectAmberBanner(analysis) {
  // Remove existing banner if present
  removeAmberBanner();

  const score  = (analysis.risk_score ?? 0).toFixed(1);
  const level  = analysis.risk_level ?? 'Suspicious';
  const isFallback = analysis.is_fallback === true;

  const banner = document.createElement('div');
  banner.id = 'fraudguard-amber-banner';

  const titleText = isFallback
    ? '⚠️ FraudGuard: Site unverified — server unavailable'
    : `⚠️ FraudGuard: Suspicious site detected (Score ${score}/100)`;

  // Use textContent for all user-visible text to prevent XSS
  const title = document.createElement('span');
  title.className = 'fg-banner-title';
  title.textContent = titleText;

  const detail = document.createElement('span');
  detail.className = 'fg-banner-detail';
  detail.textContent = analysis.explanation ?? '';

  const closeBtn = document.createElement('button');
  closeBtn.className = 'fg-banner-close';
  closeBtn.textContent = '✕ Dismiss';
  closeBtn.addEventListener('click', () => removeAmberBanner());

  banner.appendChild(title);
  banner.appendChild(detail);
  banner.appendChild(closeBtn);

  // Insert at the very top of the document body
  document.body.insertBefore(banner, document.body.firstChild);

  // Animate in
  requestAnimationFrame(() => banner.classList.add('fg-banner-show'));
}

function removeAmberBanner() {
  const banner = document.getElementById('fraudguard-amber-banner');
  if (!banner) return;
  banner.classList.remove('fg-banner-show');
  setTimeout(() => banner.remove(), 300);
}

// ------------------------------------------------------------------ //
//  Tier 2 — Full overlay  (blocking modal, score ≥ 50)
// ------------------------------------------------------------------ //

function injectOverlay(analysis) {
  removeOverlay();

  const score     = (analysis.risk_score ?? 0).toFixed(1);
  const level     = analysis.risk_level ?? 'Suspicious';
  const levelLc   = level.toLowerCase();
  const isFallback = analysis.is_fallback === true;

  const overlay = document.createElement('div');
  overlay.id = 'fraudguard-warning-popup';

  // ---- content box ----
  const box = document.createElement('div');
  box.className = 'fraudguard-popup-content';

  // ---- header ----
  const header = document.createElement('div');
  header.className = 'fraudguard-popup-header';

  const badge = document.createElement('div');
  badge.className = `fraudguard-risk-badge fraudguard-risk-${levelLc}`;
  badge.textContent = isFallback ? '⚠ UNVERIFIED' : level.toUpperCase();

  const closeBtn = document.createElement('button');
  closeBtn.className = 'fraudguard-close-btn';
  closeBtn.id = 'fraudguard-close';
  closeBtn.textContent = '×';

  header.appendChild(badge);
  header.appendChild(closeBtn);

  // ---- body ----
  const body = document.createElement('div');
  body.className = 'fraudguard-popup-body';

  const title = document.createElement('h3');
  title.className = 'fraudguard-title';
  title.textContent = isFallback ? '⚠️ Verification Unavailable' : '⚠️ Fraud Warning';

  const scoreEl = document.createElement('div');
  scoreEl.className = 'fraudguard-score';
  const scoreStrong = document.createElement('strong');
  scoreStrong.textContent = isFallback ? 'N/A (server offline)' : `${score}/100`;
  scoreEl.append('Risk Score: ', scoreStrong);

  const explanation = document.createElement('p');
  explanation.className = 'fraudguard-explanation';
  explanation.textContent = analysis.explanation ?? 'This website shows suspicious characteristics.';

  // Signal list
  const signalsEl = document.createElement('div');
  signalsEl.className = 'fraudguard-signals';
  if (analysis.signals && analysis.signals.length > 0) {
    const signalTitle = document.createElement('strong');
    signalTitle.textContent = 'Detected Issues:';
    const ul = document.createElement('ul');
    analysis.signals
      .filter(s => s.score > 0)
      .forEach(s => {
        const li = document.createElement('li');
        li.textContent = s.description;
        ul.appendChild(li);
      });
    signalsEl.appendChild(signalTitle);
    signalsEl.appendChild(ul);
  }

  const rec = document.createElement('p');
  rec.className = 'fraudguard-recommendation';
  const recStrong = document.createElement('strong');
  recStrong.textContent = 'Recommendation: ';
  rec.appendChild(recStrong);
  rec.append(analysis.recommendation ?? '');

  body.appendChild(title);
  body.appendChild(scoreEl);
  body.appendChild(explanation);
  if (analysis.signals?.some(s => s.score > 0)) body.appendChild(signalsEl);
  body.appendChild(rec);

  // ---- actions ----
  const actions = document.createElement('div');
  actions.className = 'fraudguard-popup-actions';

  const exitBtn = document.createElement('button');
  exitBtn.className = 'fraudguard-btn fraudguard-btn-danger';
  exitBtn.id = 'fraudguard-exit';
  exitBtn.textContent = 'Exit Site';

  const reportBtn = document.createElement('button');
  reportBtn.className = 'fraudguard-btn fraudguard-btn-secondary';
  reportBtn.id = 'fraudguard-report';
  reportBtn.textContent = 'Report Fraud';

  const continueBtn = document.createElement('button');
  continueBtn.className = 'fraudguard-btn fraudguard-btn-primary';
  continueBtn.id = 'fraudguard-continue';
  continueBtn.textContent = 'Continue Anyway';

  actions.appendChild(exitBtn);
  actions.appendChild(reportBtn);
  actions.appendChild(continueBtn);

  // ---- assemble ----
  box.appendChild(header);
  box.appendChild(body);
  box.appendChild(actions);
  overlay.appendChild(box);
  document.body.appendChild(overlay);

  // Animate in
  setTimeout(() => overlay.classList.add('fraudguard-show'), 10);

  // ---- event listeners ----
  closeBtn.addEventListener('click', () => removeOverlay());

  exitBtn.addEventListener('click', () => {
    window.location.href = 'about:blank';
    removeOverlay();
  });

  reportBtn.addEventListener('click', () => {
    reportBtn.disabled = true;
    reportBtn.textContent = 'Sending…';
    chrome.runtime.sendMessage(
      {
        action: 'report',
        url: analysis.url ?? getCurrentUrl(),
        reason: 'User-reported from overlay',
        riskScore: analysis.risk_score ?? null,
      },
      (response) => {
        if (chrome.runtime.lastError || !response?.success) {
          reportBtn.textContent = 'Report failed';
        } else {
          reportBtn.textContent = '✓ Reported';
        }
        setTimeout(() => removeOverlay(), 1500);
      },
    );
  });

  continueBtn.addEventListener('click', () => {
    removeOverlay();
    // Remember the user's decision for this session so the overlay doesn't
    // re-appear when they revisit the same URL.
    try {
      localStorage.setItem('fraudguard_ack_' + (analysis.url ?? currentUrl), '1');
    } catch (_) { /* localStorage may be blocked on some pages */ }
  });

  // Click on the dark backdrop closes the overlay
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) removeOverlay();
  });
}

function removeOverlay() {
  const popup = document.getElementById('fraudguard-warning-popup');
  if (!popup) return;
  popup.classList.remove('fraudguard-show');
  setTimeout(() => popup.remove(), 300);
}

// ------------------------------------------------------------------ //
//  Convenience
// ------------------------------------------------------------------ //

function removeAllWarnings() {
  removeAmberBanner();
  removeOverlay();
}

// ------------------------------------------------------------------ //
//  URL monitoring
// ------------------------------------------------------------------ //

/**
 * Kick off an immediate analysis, then poll every second to detect SPA
 * navigation (URL changes without a full page reload).
 *
 * NOTE: The interval variable is named `lastUrl` — not `currentUrl` — to
 * avoid shadowing the module-level `currentUrl` tracking variable.
 */
function monitorUrlChanges() {
  analyzeCurrentUrl();

  let lastUrl = getCurrentUrl();
  setInterval(() => {
    const newUrl = getCurrentUrl();
    if (newUrl !== lastUrl) {
      lastUrl = newUrl;
      analyzeCurrentUrl();
    }
  }, 1000);
}

// ------------------------------------------------------------------ //
//  Skip acknowledged URLs
// ------------------------------------------------------------------ //

/**
 * Return true if the user previously clicked "Continue Anyway" for this URL
 * in the current session, meaning the overlay should not re-appear.
 */
function isAcknowledged(url) {
  try {
    return localStorage.getItem('fraudguard_ack_' + url) === '1';
  } catch (_) {
    return false;
  }
}

// ------------------------------------------------------------------ //
//  Initialisation
// ------------------------------------------------------------------ //

function init() {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', monitorUrlChanges);
  } else {
    monitorUrlChanges();
  }
}

init();
