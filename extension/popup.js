/**
 * FraudGuard — Toolbar Popup Script
 *
 * Shows the current tab's URL, the backend connection status, and the
 * latest risk analysis result. Lets the user manually trigger an analysis.
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

// ------------------------------------------------------------------ //
//  Connection status
// ------------------------------------------------------------------ //

/**
 * Ping the background worker which in turn hits /health on the backend.
 * Updates the connection pill UI with the result.
 */
function checkConnection() {
  const pill  = $('connectionPill');
  const label = $('connectionLabel');

  pill.className  = 'connection-pill checking';
  label.textContent = 'Checking…';

  chrome.runtime.sendMessage({ action: 'ping' }, (response) => {
    if (chrome.runtime.lastError || !response) {
      pill.className  = 'connection-pill offline';
      label.textContent = 'Offline';
      return;
    }
    if (response.online) {
      pill.className  = 'connection-pill online';
      label.textContent = 'Server online';
    } else {
      pill.className  = 'connection-pill offline';
      label.textContent = 'Server offline';
    }
  });
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

  $('analyzeBtn').disabled  = true;
  $('analyzeBtn').textContent = '⏳ Analyzing…';
  setStatus('Analyzing…', '', 'Default');

  chrome.runtime.sendMessage({ action: 'analyze', url: tab.url }, (response) => {
    $('analyzeBtn').disabled  = false;
    $('analyzeBtn').textContent = '🔍 Analyze Current Page';

    if (chrome.runtime.lastError) {
      setStatus('Error: ' + chrome.runtime.lastError.message, '', 'Default');
      return;
    }

    if (response?.success) {
      displayResult(response.data);
    } else {
      setStatus('Analysis failed', response?.error ?? '', 'Default');
    }
  });
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
  const colors  = LEVEL_COLORS[level] ?? LEVEL_COLORS.Default;
  const statusEl = $('status');
  const scoreEl  = $('scoreBadge');

  $('statusText').textContent       = text;
  $('statusExplanation').textContent = explanation;
  statusEl.style.background         = colors.bg;
  statusEl.style.color              = colors.text;

  if (score !== null) {
    scoreEl.style.display          = 'inline-block';
    scoreEl.textContent            = Math.round(score);
    scoreEl.style.background       = colors.badge;
    scoreEl.style.color            = 'white';
  } else {
    scoreEl.style.display = 'none';
  }
}

// ------------------------------------------------------------------ //
//  XSS helper
// ------------------------------------------------------------------ //

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ------------------------------------------------------------------ //
//  Initialisation
// ------------------------------------------------------------------ //

async function init() {
  await updatePopup();
  checkConnection();

  $('analyzeBtn').addEventListener('click', analyzeCurrentPage);

  // Refresh popup state every 3 seconds to pick up tab changes
  setInterval(updatePopup, 3000);
  // Recheck backend connection every 15 seconds
  setInterval(checkConnection, 15000);
}

init();
