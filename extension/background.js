/**
 * Background Service Worker for FraudGuard
 * Handles API communication with backend and manages fraud detection state
 */

// Backend API URL - Update this to your backend URL
const BACKEND_URL = 'http://localhost:8000';

// Risk thresholds matching backend configuration
const RISK_THRESHOLDS = {
  SAFE: 30,
  SUSPICIOUS: 70,
  DANGEROUS: 100
};

// Cache to store analysis results (URL -> analysis result)
const analysisCache = new Map();

/**
 * Analyze a URL by calling the backend API
 * @param {string} url - The URL to analyze
 * @returns {Promise<Object>} Analysis result with risk score and details
 */
async function analyzeUrl(url) {
  // #region agent log
  fetch('http://127.0.0.1:7243/ingest/b7dbe784-3ced-4b54-9c6b-2d3f908929e5', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'background.js:24', message: 'analyzeUrl entry', data: { url: url, backendUrl: BACKEND_URL }, timestamp: Date.now(), sessionId: 'debug-session', runId: 'run1', hypothesisId: 'A,B,C' }) }).catch(() => { });
  // #endregion

  // Check cache first
  if (analysisCache.has(url)) {
    console.log('[FraudGuard] Using cached result for:', url);
    // #region agent log
    fetch('http://127.0.0.1:7243/ingest/b7dbe784-3ced-4b54-9c6b-2d3f908929e5', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'background.js:27', message: 'cache hit', data: { url: url }, timestamp: Date.now(), sessionId: 'debug-session', runId: 'run1', hypothesisId: 'A' }) }).catch(() => { });
    // #endregion
    return analysisCache.get(url);
  }

  try {
    console.log('[FraudGuard] Analyzing URL:', url);

    // #region agent log
    const beforeFetchLog = { location: 'background.js:42', message: 'before fetch', data: { url: url, backendUrl: BACKEND_URL, endpoint: `${BACKEND_URL}/analyze` }, timestamp: Date.now(), sessionId: 'debug-session', runId: 'run1', hypothesisId: 'A,B,C' };
    console.log('[DEBUG LOG]', beforeFetchLog);
    fetch('http://127.0.0.1:7243/ingest/b7dbe784-3ced-4b54-9c6b-2d3f908929e5', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(beforeFetchLog) }).catch(err => console.error('[DEBUG LOG SEND FAILED]', err));
    // #endregion

    const response = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    // #region agent log
    fetch('http://127.0.0.1:7243/ingest/b7dbe784-3ced-4b54-9c6b-2d3f908929e5', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'background.js:45', message: 'after fetch', data: { ok: response.ok, status: response.status, statusText: response.statusText, headers: Object.fromEntries(response.headers.entries()) }, timestamp: Date.now(), sessionId: 'debug-session', runId: 'run1', hypothesisId: 'B,C,D' }) }).catch(() => { });
    // #endregion

    if (!response.ok) {
      // #region agent log
      fetch('http://127.0.0.1:7243/ingest/b7dbe784-3ced-4b54-9c6b-2d3f908929e5', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'background.js:48', message: 'response not ok', data: { status: response.status, statusText: response.statusText }, timestamp: Date.now(), sessionId: 'debug-session', runId: 'run1', hypothesisId: 'D' }) }).catch(() => { });
      // #endregion
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    // #region agent log
    fetch('http://127.0.0.1:7243/ingest/b7dbe784-3ced-4b54-9c6b-2d3f908929e5', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'background.js:52', message: 'response data received', data: { riskScore: data.risk_score, riskLevel: data.risk_level }, timestamp: Date.now(), sessionId: 'debug-session', runId: 'run1', hypothesisId: 'E' }) }).catch(() => { });
    // #endregion

    // Cache the result
    analysisCache.set(url, data);

    console.log('[FraudGuard] Analysis result:', data);
    return data;

  } catch (error) {
    console.error('[FraudGuard] Error analyzing URL:', error);
    // #region agent log
    const errorLog = { location: 'background.js:79', message: 'fetch error caught', data: { errorName: error.name, errorMessage: error.message, errorStack: error.stack?.substring(0, 500) }, timestamp: Date.now(), sessionId: 'debug-session', runId: 'run1', hypothesisId: 'A,B,C' };
    console.log('[DEBUG LOG]', errorLog);
    fetch('http://127.0.0.1:7243/ingest/b7dbe784-3ced-4b54-9c6b-2d3f908929e5', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(errorLog) }).catch(err => console.error('[DEBUG LOG SEND FAILED]', err));
    // #endregion
    return {
      url: url,
      risk_score: 0,
      risk_level: 'Safe',
      signals: [],
      explanation: 'Unable to analyze URL. Please check backend connection.',
      recommendation: 'Proceed with caution.',
      error: error.message
    };
  }
}

/**
 * Listen for messages from content script
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('[FraudGuard] Message received:', request);

  if (request.action === 'analyze') {
    // Analyze the URL asynchronously
    analyzeUrl(request.url)
      .then(result => {
        sendResponse({ success: true, data: result });
      })
      .catch(error => {
        sendResponse({ success: false, error: error.message });
      });

    // Return true to indicate we'll send response asynchronously
    return true;
  }

  if (request.action === 'getAnalysis') {
    // Return cached analysis if available
    const cached = analysisCache.get(request.url);
    sendResponse({ success: true, cached: cached !== undefined, data: cached });
    return false;
  }
});

/**
 * Listen for tab updates to clear cache when navigating away
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    // Optionally clear cache for old URL when navigating
    // This keeps cache fresh but allows same-page checks
  }
});

/**
 * Clear cache when extension is installed/updated
 */
chrome.runtime.onInstalled.addListener(() => {
  console.log('[FraudGuard] Extension installed/updated');
  analysisCache.clear();
});
