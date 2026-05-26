/**
 * FraudGuard — Background Service Worker
 *
 * Responsibilities:
 *  - Receive analyze/report messages from content scripts and the popup
 *  - Call the FraudGuard backend API
 *  - Cache results in chrome.storage.local (1-hour TTL)
 *  - Keep the toolbar badge updated with the current site's risk level
 *  - Surface a "backend unavailable" warning when the server is unreachable
 */

// ------------------------------------------------------------------ //
//  Configuration
// ------------------------------------------------------------------ //

/** Base URL of the FraudGuard backend. Change this when deploying remotely. */
const BACKEND_URL = 'http://localhost:8000';

/** Cache entries older than this are re-fetched. */
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

/** Badge colours matching the risk classification system. */
const BADGE_COLORS = {
  safe:        '#4caf50',   // green
  suspicious:  '#ff9800',   // orange
  dangerous:   '#f44336',   // red
  fallback:    '#ffeb3b',   // yellow — backend unavailable
  clear:       '#888888',   // grey — non-analyzable page
};

// ------------------------------------------------------------------ //
//  Cache helpers  (chrome.storage.local — survives service worker restart)
// ------------------------------------------------------------------ //

/**
 * Return a cached analysis result for the given URL if it exists and is
 * still within the TTL window, otherwise return null.
 */
async function getCached(url) {
  try {
    const key = `fg_cache_${url}`;
    const stored = await chrome.storage.local.get(key);
    const entry = stored[key];
    if (entry && (Date.now() - entry.timestamp) < CACHE_TTL_MS) {
      console.log('[FraudGuard] Cache hit:', url);
      return entry.data;
    }
  } catch (err) {
    console.warn('[FraudGuard] Cache read error:', err);
  }
  return null;
}

/**
 * Persist an analysis result keyed by URL.
 * Fallback results are never cached so the backend is retried immediately
 * on the next navigation once the server recovers.
 */
async function setCached(url, data) {
  if (data.is_fallback) return;
  try {
    const key = `fg_cache_${url}`;
    await chrome.storage.local.set({ [key]: { data, timestamp: Date.now() } });
  } catch (err) {
    console.warn('[FraudGuard] Cache write error:', err);
  }
}

/**
 * Evict the cached result for a URL (called on tab navigation).
 */
async function evictCached(url) {
  if (!url) return;
  try {
    await chrome.storage.local.remove(`fg_cache_${url}`);
  } catch (err) {
    console.warn('[FraudGuard] Cache evict error:', err);
  }
}

// ------------------------------------------------------------------ //
//  Badge helpers
// ------------------------------------------------------------------ //

/**
 * Update the toolbar badge for a specific tab to reflect the analysis result.
 * @param {number} tabId
 * @param {object} result  AnalyzeResponse object (or fallback object)
 */
function updateBadge(tabId, result) {
  if (!tabId) return;

  const score = result.risk_score ?? 0;
  const level = (result.risk_level ?? 'Safe').toLowerCase();
  const isFallback = result.is_fallback === true;

  let text = '';
  let color = BADGE_COLORS.safe;

  if (isFallback) {
    text = '!';
    color = BADGE_COLORS.fallback;
  } else if (level === 'dangerous') {
    text = String(Math.round(score));
    color = BADGE_COLORS.dangerous;
  } else if (level === 'suspicious') {
    text = String(Math.round(score));
    color = BADGE_COLORS.suspicious;
  } else {
    text = '';
    color = BADGE_COLORS.safe;
  }

  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

/**
 * Clear the badge on a tab (used for chrome://, extension:// pages etc.).
 */
function clearBadge(tabId) {
  if (!tabId) return;
  chrome.action.setBadgeText({ text: '', tabId });
  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.clear, tabId });
}

// ------------------------------------------------------------------ //
//  Core analysis
// ------------------------------------------------------------------ //

/**
 * Analyze a URL — check cache first, then call the backend.
 *
 * On backend failure returns a degraded-mode result with is_fallback:true
 * and risk_score:70 so the content script always surfaces a warning rather
 * than silently passing the site as safe.
 *
 * @param {string} url
 * @returns {Promise<object>}  AnalyzeResponse-shaped object
 */
async function analyzeUrl(url) {
  // 1. Cache check
  const cached = await getCached(url);
  if (cached) return cached;

  // 2. Backend call
  try {
    console.log('[FraudGuard] Fetching analysis for:', url);

    const response = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    console.log('[FraudGuard] Analysis result:', data.risk_level, data.risk_score);

    // 3. Cache successful result
    await setCached(url, data);
    return data;

  } catch (error) {
    // Backend is unreachable or returned an error.
    // Return a HIGH-CAUTION fallback — never a safe result — so the overlay
    // fires and the user is alerted that verification could not be completed.
    console.error('[FraudGuard] Backend error:', error.message);
    return {
      url,
      risk_score: 70,
      risk_level: 'Suspicious',
      signals: [],
      explanation:
        '⚠️ FraudGuard could not verify this site — the analysis server is unavailable. ' +
        'Treat this site with caution until verification can be completed.',
      recommendation:
        'The fraud detection server is not reachable. Avoid entering sensitive ' +
        'financial information until the connection is restored.',
      is_fallback: true,
      error: error.message,
    };
  }
}

/**
 * Submit a fraud report to the backend.
 * @param {string} url
 * @param {string|null} reason
 * @param {number|null} riskScore
 * @returns {Promise<object>}
 */
async function reportFraud(url, reason = null, riskScore = null) {
  try {
    const response = await fetch(`${BACKEND_URL}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, reason, risk_score: riskScore }),
    });
    if (!response.ok) throw new Error(`Report API error: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error('[FraudGuard] Report failed:', error.message);
    return { status: 'error', error: error.message };
  }
}

// ------------------------------------------------------------------ //
//  Message listener
// ------------------------------------------------------------------ //

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = sender.tab?.id ?? null;

  // --- analyze ------------------------------------------------------- //
  if (request.action === 'analyze') {
    const url = request.url;

    // Reject non-HTTP URLs immediately
    if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
      sendResponse({ success: false, error: 'invalid URL' });
      return false;
    }

    analyzeUrl(url)
      .then(result => {
        updateBadge(tabId, result);
        sendResponse({ success: true, data: result });
      })
      .catch(err => {
        sendResponse({ success: false, error: err.message });
      });

    return true; // keep channel open for async response
  }

  // --- report -------------------------------------------------------- //
  if (request.action === 'report') {
    reportFraud(request.url, request.reason ?? null, request.riskScore ?? null)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  // --- ping (popup connection check) --------------------------------- //
  if (request.action === 'ping') {
    fetch(`${BACKEND_URL}/health`)
      .then(r => sendResponse({ online: r.ok }))
      .catch(() => sendResponse({ online: false }));
    return true;
  }
});

// ------------------------------------------------------------------ //
//  Tab lifecycle
// ------------------------------------------------------------------ //

/**
 * When a tab starts loading a new URL, evict the cached result for that URL
 * so stale data is never shown on the next analysis.
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    // Evict cache so the next analysis fetches fresh data
    evictCached(tab.url);

    // Clear badge while the page loads
    if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) {
      clearBadge(tabId);
    }
  }
});

// ------------------------------------------------------------------ //
//  Startup
// ------------------------------------------------------------------ //

chrome.runtime.onInstalled.addListener(() => {
  console.log('[FraudGuard] Extension installed / updated.');
  // Clear any stale cache from previous installs
  chrome.storage.local.clear();
});
