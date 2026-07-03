/**
 * FraudGuard — Toolbar Popup Script
 *
 * Shows the current tab's URL, the backend connection status, and the
 * latest risk analysis result. Lets the user manually trigger an analysis.
 *
 * All background communication goes through `sendToBackground`, which promisi-
 * fies chrome.runtime.sendMessage, surfaces lastError instead of throwing, and
 * retries once — the service worker may be asleep on the first message and Chrome
 * occasionally reports "Could not establish connection" until it has spun up.
 */

// ------------------------------------------------------------------ //
//  Risk level → colour mapping
// ------------------------------------------------------------------ //

const LEVEL_COLORS = {
  Safe:       { bg: '#e8f5e9', text: '#2e7d32', badge: '#4caf50' },
  Suspicious: { bg: '#fff3e0', text: '#e65100', badge: '#ff9800' },
  Dangerous:  { bg: '#ffebee', text: '#c62828', badge: '#f44336' },
  Fallback:   { bg: '#fff8e1', text: '#795548', badge: '#ffeb3b' },
  Default:    { bg: '#f5f5f5', text: '#333',    badge: '#999'    },
};

// ------------------------------------------------------------------ //
//  DOM helpers
// ------------------------------------------------------------------ //

const $ = id => document.getElementById(id);

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// ------------------------------------------------------------------ //
//  Background messaging
// ------------------------------------------------------------------ //

/**
 * Send a single message to the background service worker.
 * Resolves with the worker's response, or `{ __error: string }` when the
 * worker could not be reached / did not reply. Never rejects.
 */
function sendMessageOnce(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        const err = chrome.runtime.lastError;
        if (err) {
          resolve({ __error: err.message });
        } else if (response == null) {
          resolve({ __error: 'no response from background worker' });
        } else {
          resolve(response);
        }
      });
    } catch (e) {
      resolve({ __error: e?.message ?? String(e) });
    }
  });
}

/**
 * Send a message, retrying once after a short delay if the first attempt
 * failed to reach the worker (it may have been waking from dormant).
 */
async function sendToBackground(message) {
  let res = await sendMessageOnce(message);
  if (res.__error) {
    await delay(500);
    res = await sendMessageOnce(message);
  }
  return res;
}

// ------------------------------------------------------------------ //
//  Connection status
// ------------------------------------------------------------------ //

/**
 * Ping the background worker, which in turn hits /health on the backend, and
 * update the connection pill UI. Distinguishes three states:
 *   - worker unreachable  → "Offline"        (extension/service-worker problem)
 *   - worker up, API down → "Server offline"  (backend unreachable)
 *   - worker up, API up   → "Server online"
 */
async function checkConnection() {
  const pill = $('connectionPill');
  const label = $('connectionLabel');

  pill.className = 'connection-pill checking';
  label.textContent = 'Checking…';

  const res = await sendToBackground({ action: 'ping' });

  if (res.__error) {
    pill.className = 'connection-pill offline';
    label.textContent = 'Offline';
    return;
  }

  if (res.online) {
    pill.className = 'connection-pill online';
    label.textContent = 'Server online';
  } else {
    pill.className = 'connection-pill offline';
    label.textContent = 'Server offline';
  }
}

// ------------------------------------------------------------------ //
//  Current tab
// ------------------------------------------------------------------ //

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// ------------------------------------------------------------------ //
//  Popup state
// ------------------------------------------------------------------ //

async function updatePopup() {
  const tab = await getCurrentTab();
  const urlEl = $('currentUrl');

  if (!tab || !tab.url) {
    urlEl.innerHTML = '<span class="current-url-label">Current page</span>No active tab';
    setStatus('No active tab', '', 'Default');
    $('analyzeBtn').disabled = true;
    return;
  }

  urlEl.innerHTML = `<span class="current-url-label">Current page</span>${escapeHtml(tab.url)}`;

  if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) {
    setStatus('Cannot analyze this page type', '', 'Default');
    $('analyzeBtn').disabled = true;
  } else {
    $('analyzeBtn').disabled = false;
    setStatus('Monitoring active', '', 'Default');
  }
}

// ------------------------------------------------------------------ //
//  Manual analysis
// ------------------------------------------------------------------ //

async function analyzeCurrentPage() {
  const tab = await getCurrentTab();

  if (!tab?.url?.startsWith('http')) {
    setStatus('Cannot analyze this page type', '', 'Default');
    return;
  }

  const btn = $('analyzeBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Analyzing…';
  setStatus('Analyzing…', '', 'Default');

  const res = await sendToBackground({ action: 'analyze', url: tab.url });

  btn.disabled = false;
  btn.textContent = '🔍 Analyze Current Page';

  if (res.__error) {
    setStatus('Connection error', res.__error, 'Default');
    return;
  }

  if (res.success) {
    displayResult(res.data);
  } else {
    setStatus('Analysis failed', res.error ?? '', 'Default');
  }
}

// ------------------------------------------------------------------ //
//  Result display
// ------------------------------------------------------------------ //

function displayResult(analysis) {
  const level      = analysis.risk_level ?? 'Safe';
  const score      = analysis.risk_score ?? 0;
  const isFallback = analysis.is_fallback === true;

  if (isFallback) {
    setStatus('⚠ Server unavailable', analysis.explanation ?? '', 'Fallback', null);
    $('lastCheck').textContent = 'Last check: now (degraded)';
    return;
  }

  const icons = { Safe: '✓', Suspicious: '⚠', Dangerous: '⛔' };
  const icon  = icons[level] ?? '';
  const label = `${icon} ${level} — Score ${score.toFixed(1)}/100`;

  setStatus(label, analysis.explanation ?? '', level, score);
  $('lastCheck').textContent = `Last check: ${new Date().toLocaleTimeString()}`;
}

function setStatus(text, explanation, level, score = null) {
  const colors   = LEVEL_COLORS[level] ?? LEVEL_COLORS.Default;
  const statusEl = $('status');
  const scoreEl  = $('scoreBadge');

  $('statusText').textContent        = text;
  $('statusExplanation').textContent = explanation;
  statusEl.style.background          = colors.bg;
  statusEl.style.color               = colors.text;

  if (score !== null) {
    scoreEl.style.display    = 'inline-block';
    scoreEl.textContent      = Math.round(score);
    scoreEl.style.background = colors.badge;
    scoreEl.style.color      = 'white';
  } else {
    scoreEl.style.display = 'none';
  }
}

// ------------------------------------------------------------------ //
//  XSS helper
// ------------------------------------------------------------------ //

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ------------------------------------------------------------------ //
//  Initialisation
// ------------------------------------------------------------------ //

// Interval handles so they can be cleared if the popup is torn down.
let popupInterval = null;
let connInterval  = null;

async function init() {
  await updatePopup();
  checkConnection();

  $('analyzeBtn').addEventListener('click', analyzeCurrentPage);

  // Refresh popup state every 3 seconds to pick up tab changes.
  popupInterval = setInterval(updatePopup, 3000);
  // Recheck backend connection every 15 seconds.
  connInterval = setInterval(checkConnection, 15000);
}

// Stop the polling loops when the popup closes so we don't leak timers or
// fire messages at a torn-down context.
window.addEventListener('unload', () => {
  if (popupInterval) clearInterval(popupInterval);
  if (connInterval) clearInterval(connInterval);
});

init();
