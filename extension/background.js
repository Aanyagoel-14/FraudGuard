/**
 * FraudGuard — Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 *  - Receive analyze/report/ping messages from content scripts and the popup
 *  - Call the FraudGuard backend API (with timeouts so cold starts can't hang)
 *  - Cache results in chrome.storage.local (1-hour TTL)
 *  - Keep the toolbar badge updated with the current site's risk level
 *  - Surface a "backend unavailable" fallback when the server is unreachable
 *
 * MV3 reliability notes:
 *  - The message listener is registered synchronously at the top level so the
 *    service worker always has a receiver as soon as Chrome wakes it. All
 *    handler logic funnels through a single async `handleMessage`, and every
 *    code path resolves to a value that is handed to `sendResponse`. The
 *    listener always returns `true`, keeping the message port open for the
 *    asynchronous reply. This prevents "The message port closed before a
 *    response was received" and guarantees senders never hang.
 *  - Every network call is wrapped in an AbortController timeout so a slow or
 *    sleeping backend (e.g. Render free-tier cold start) can't keep the worker
 *    blocked indefinitely or leave the popup stuck on "Checking…".
 */

// ------------------------------------------------------------------ //
//  Configuration
// ------------------------------------------------------------------ //

/** Base URL of the FraudGuard backend. Change this when deploying remotely. */
const BACKEND_URL = 'https://fraudguard-8yd6.onrender.com';

/** Cache entries older than this are re-fetched. */
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Network timeouts (ms). The analyze timeout is deliberately generous because
 * the backend runs on a free tier that can cold-start for ~30s; the health
 * probe is shorter so the popup gets a definitive answer quickly.
 */
const HEALTH_TIMEOUT_MS  = 10000;
const ANALYZE_TIMEOUT_MS = 25000;
const REPORT_TIMEOUT_MS  = 15000;

/** Badge colours matching the risk classification system. */
const BADGE_COLORS = {
  safe:        '#4caf50',   // green
  suspicious:  '#ff9800',   // orange
  dangerous:   '#f44336',   // red
  fallback:    '#ffeb3b',   // yellow — backend unavailable
  clear:       '#888888',   // grey — non-analyzable page
};

// ------------------------------------------------------------------ //
//  Small utilities
// ------------------------------------------------------------------ //

/** True for http(s) URLs — the only pages we can meaningfully analyze. */
function isHttpUrl(url) {
  return typeof url === 'string' &&
    (url.startsWith('http://') || url.startsWith('https://'));
}

/**
 * fetch() with an AbortController-based timeout so a hung/sleeping backend
 * never blocks the service worker forever.
 */
async function fetchWithTimeout(resource, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(resource, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

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
 * Wrapped so a stale tabId (tab closed/navigated before the async result
 * arrives) can never throw an unhandled error and destabilize the worker.
 *
 * @param {number|null} tabId
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

  setBadge(tabId, text, color);
}

/**
 * Clear the badge on a tab (used for chrome://, extension:// pages etc.).
 */
function clearBadge(tabId) {
  if (!tabId) return;
  setBadge(tabId, '', BADGE_COLORS.clear);
}

/**
 * Low-level badge writer. chrome.action.* reject (or throw) when the target
 * tab no longer exists; swallow those since a gone tab needs no badge.
 */
function setBadge(tabId, text, color) {
  try {
    Promise.resolve(chrome.action.setBadgeText({ text, tabId })).catch(() => {});
    Promise.resolve(chrome.action.setBadgeBackgroundColor({ color, tabId })).catch(() => {});
  } catch (_) {
    /* tab gone — nothing to update */
  }
}

// ------------------------------------------------------------------ //
//  Core analysis
// ------------------------------------------------------------------ //

/**
 * Build a HIGH-CAUTION fallback result. Returned whenever the backend can't be
 * reached so the UI always warns the user rather than silently passing a site
 * as safe. Never cached (see setCached).
 */
function buildFallback(url, errorMessage) {
  return {
    url,
    risk_score: 70,
    risk_level: 'Suspicious',
    signals: [],
    explanation:
      '⚠️ FraudGuard could not verify this site — the analysis server is ' +
      'unavailable. Treat this site with caution until verification can be ' +
      'completed.',
    recommendation:
      'The fraud detection server is not reachable. Avoid entering sensitive ' +
      'financial information until the connection is restored.',
    is_fallback: true,
    error: errorMessage,
  };
}

/**
 * Analyze a URL — check cache first, then call the backend.
 * On backend failure returns a degraded-mode fallback (see buildFallback).
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

    const response = await fetchWithTimeout(
      `${BACKEND_URL}/analyze`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      },
      ANALYZE_TIMEOUT_MS,
    );

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    console.log('[FraudGuard] Analysis result:', data.risk_level, data.risk_score);

    // 3. Cache successful result
    await setCached(url, data);
    return data;

  } catch (error) {
    const reason = error.name === 'AbortError'
      ? 'timeout — backend did not respond in time'
      : error.message;
    console.error('[FraudGuard] Backend error:', reason);
    return buildFallback(url, reason);
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
    const response = await fetchWithTimeout(
      `${BACKEND_URL}/report`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, reason, risk_score: riskScore }),
      },
      REPORT_TIMEOUT_MS,
    );
    if (!response.ok) throw new Error(`Report API error: ${response.status}`);
    return await response.json();
  } catch (error) {
    const reason2 = error.name === 'AbortError' ? 'timeout' : error.message;
    console.error('[FraudGuard] Report failed:', reason2);
    return { status: 'error', error: reason2 };
  }
}

/**
 * Probe the backend /health endpoint. Returns true only on a 2xx response.
 * Never throws — a timeout or network error resolves to false.
 */
async function checkBackendHealth() {
  try {
    const response = await fetchWithTimeout(
      `${BACKEND_URL}/health`,
      { method: 'GET' },
      HEALTH_TIMEOUT_MS,
    );
    return response.ok;
  } catch (error) {
    const reason = error.name === 'AbortError' ? 'timeout' : error.message;
    console.warn('[FraudGuard] Health check failed:', reason);
    return false;
  }
}

// ------------------------------------------------------------------ //
//  Message routing
// ------------------------------------------------------------------ //

/**
 * Resolve a message to the object that should be sent back to the caller.
 * Always resolves (errors become an error-shaped result) so the port is
 * never left hanging.
 *
 * @param {object} request
 * @param {chrome.runtime.MessageSender} sender
 * @returns {Promise<object>}
 */
async function handleMessage(request, sender) {
  const action = request?.action;

  switch (action) {
    // --- ping (popup connection check) ------------------------------- //
    case 'ping': {
      const online = await checkBackendHealth();
      // `ok` confirms the service worker itself answered; `online` reflects
      // backend reachability. This lets the popup tell the two apart.
      return { ok: true, online };
    }

    // --- analyze ----------------------------------------------------- //
    case 'analyze': {
      const url = request.url;
      if (!isHttpUrl(url)) {
        return { success: false, error: 'invalid URL' };
      }
      const result = await analyzeUrl(url);
      updateBadge(sender?.tab?.id ?? null, result);
      return { success: true, data: result };
    }

    // --- report ------------------------------------------------------ //
    case 'report': {
      const data = await reportFraud(
        request.url,
        request.reason ?? null,
        request.riskScore ?? null,
      );
      return { success: true, data };
    }

    default:
      return { success: false, error: `unknown action: ${action}` };
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  handleMessage(request, sender)
    .then(sendResponse)
    .catch((err) => {
      // Should never happen (handleMessage swallows its own errors), but keep
      // the contract: always send a response so the caller never hangs.
      console.error('[FraudGuard] Unhandled message error:', err);
      sendResponse({ success: false, error: String(err?.message ?? err) });
    });

  // Always return true: every branch responds asynchronously.
  return true;
});

// ------------------------------------------------------------------ //
//  Tab lifecycle
// ------------------------------------------------------------------ //

/**
 * When a tab starts loading a new URL, evict the cached result for that URL
 * so stale data is never shown on the next analysis, and clear the badge on
 * non-analyzable pages.
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    evictCached(tab.url);
    if (!isHttpUrl(tab.url)) {
      clearBadge(tabId);
    }
  }
});

// ------------------------------------------------------------------ //
//  Startup
// ------------------------------------------------------------------ //

chrome.runtime.onInstalled.addListener(() => {
  console.log('[FraudGuard] Extension installed / updated.');
  // Clear any stale cache from previous installs.
  chrome.storage.local.clear();
});
