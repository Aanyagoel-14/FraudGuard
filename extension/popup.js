/**
 * FraudGuard — Toolbar Popup (v2)
 *
 * Dark cybersecurity UI with animated SVG gauge, 6-signal breakdown,
 * scan animation, auto-analyze on open (cache-first), and report button.
 */

// ── Constants ────────────────────────────────────────────────────────── //

// Must match background.js CACHE_TTL_MS
const CACHE_TTL_MS = 60 * 60 * 1000;

// 2π × r(80) × 270/360 = 502.655 × 0.75 = 376.99 → 377
const GAUGE_ARC_LENGTH = 377;

const LEVEL_COLORS = {
  Safe:       { gauge: '#4caf50', text: '#4caf50', border: '#4caf5060', bg: 'rgba(76,175,80,0.08)'   },
  Suspicious: { gauge: '#ff9800', text: '#ff9800', border: '#ff980060', bg: 'rgba(255,152,0,0.08)'   },
  Dangerous:  { gauge: '#f44336', text: '#f44336', border: '#f4433660', bg: 'rgba(244,67,54,0.08)'   },
  Fallback:   { gauge: '#ffeb3b', text: '#ffeb3b', border: '#ffeb3b60', bg: 'rgba(255,235,59,0.08)'  },
  Default:    { gauge: '#8b949e', text: '#6e7681', border: '#30363d',   bg: '#161b22'                 },
};

// Inline SVG icons for each signal (stroke-based, uses currentColor)
const SIGNAL_ICONS = {
  'URL Similarity': `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="5.5" cy="10.5" r="3.5" stroke="currentColor" stroke-width="1.4"/>
    <circle cx="10.5" cy="5.5" r="3.5" stroke="currentColor" stroke-width="1.4"/>
    <line x1="7.9" y1="8.1" x2="8.1" y2="7.9" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  </svg>`,
  'Domain Age': `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.4"/>
    <polyline points="8,4 8,8 11,10" stroke="currentColor" stroke-width="1.4"
      stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`,
  'SSL/HTTPS': `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect x="2.5" y="7" width="11" height="7.5" rx="1.5" stroke="currentColor" stroke-width="1.4"/>
    <path d="M5.2 7V5A2.8 2.8 0 0110.8 5v2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
    <circle cx="8" cy="10.8" r="1.1" fill="currentColor"/>
  </svg>`,
  'Keyword Pattern': `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="6.5" cy="6.5" r="4.5" stroke="currentColor" stroke-width="1.4"/>
    <line x1="9.9" y1="9.9" x2="14" y2="14" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
  </svg>`,
  'URL Structure': `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
    <polyline points="4.5,5 2,8 4.5,11" stroke="currentColor" stroke-width="1.4"
      stroke-linecap="round" stroke-linejoin="round"/>
    <polyline points="11.5,5 14,8 11.5,11" stroke="currentColor" stroke-width="1.4"
      stroke-linecap="round" stroke-linejoin="round"/>
    <line x1="9.5" y1="3" x2="6.5" y2="13" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
  </svg>`,
  'Safe Browsing': `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M8 1L1.5 3.8V8c0 3.7 2.8 7 6.5 7.5C11.7 15 14.5 11.7 14.5 8V3.8L8 1z"
      stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
    <polyline points="5.5,8.5 7,10 10.5,6.5" stroke="currentColor" stroke-width="1.4"
      stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`,
};

const SIGNAL_ORDER = [
  'URL Similarity', 'Domain Age', 'SSL/HTTPS',
  'Keyword Pattern', 'URL Structure', 'Safe Browsing',
];

// ── Globals ──────────────────────────────────────────────────────────── //

let currentAnalysis = null;
let scanStartTime   = 0;

// ── DOM helper ───────────────────────────────────────────────────────── //

const $ = id => document.getElementById(id);

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// ── Background messaging ─────────────────────────────────────────────── //

/**
 * Promisified chrome.runtime.sendMessage. Resolves with the worker's response,
 * or `{ __error: string }` when the worker could not be reached. Never rejects.
 */
function sendMessageOnce(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        const err = chrome.runtime.lastError;
        if (err) resolve({ __error: err.message });
        else if (response == null) resolve({ __error: 'no response' });
        else resolve(response);
      });
    } catch (e) {
      resolve({ __error: e?.message ?? String(e) });
    }
  });
}

/**
 * Send a message, retrying once after a short delay if the first attempt
 * couldn't reach the service worker — it may have been waking from dormant,
 * which is what produces "Could not establish connection. Receiving end does
 * not exist" on the very first message.
 */
async function sendToBackground(message) {
  let res = await sendMessageOnce(message);
  if (res.__error) {
    await delay(500);
    res = await sendMessageOnce(message);
  }
  return res;
}

// ── Connection check ─────────────────────────────────────────────────── //

async function checkConnection() {
  const pill  = $('connectionPill');
  const label = $('connectionLabel');
  pill.className    = 'connection-pill checking';
  label.textContent = 'Checking';

  const res = await sendToBackground({ action: 'ping' });
  const online = !res.__error && res.online === true;

  pill.className    = online ? 'connection-pill online' : 'connection-pill offline';
  label.textContent = online ? 'Online' : 'Offline';
}

// ── Tab helper ───────────────────────────────────────────────────────── //

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// ── Cache reader ─────────────────────────────────────────────────────── //

async function loadCachedResult(url) {
  try {
    const key   = `fg_cache_${url}`;
    const store = await chrome.storage.local.get(key);
    const entry = store[key];
    if (entry && (Date.now() - entry.timestamp) < CACHE_TTL_MS) {
      return entry.data;
    }
  } catch (_) { /* storage unavailable */ }
  return null;
}

// ── Gauge animation ──────────────────────────────────────────────────── //

function animateGauge(score, color) {
  const arc    = $('gaugeArc');
  const target = GAUGE_ARC_LENGTH - (score / 100) * GAUGE_ARC_LENGTH;

  // Reset arc to empty (no transition so it snaps)
  arc.style.transition        = 'none';
  arc.style.strokeDashoffset  = GAUGE_ARC_LENGTH;
  arc.setAttribute('stroke', color);

  // Force reflow, then animate to target position
  arc.getBoundingClientRect();
  arc.style.transition       = 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)';
  arc.style.strokeDashoffset = target;
}

function animateScoreCounter(target) {
  const el       = $('gaugeScore');
  const duration = 1200;
  const start    = performance.now();

  function tick(now) {
    const t     = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
    el.textContent = Math.round(eased * target);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ── Score → colour ───────────────────────────────────────────────────── //

function getScoreColor(score) {
  if (score <= 30) return '#4caf50';
  if (score <= 70) return '#ff9800';
  return '#f44336';
}

// ── Scan state ───────────────────────────────────────────────────────── //

function enterScanningState() {
  scanStartTime = Date.now();
  $('gaugeZone').classList.add('scanning');
  $('gaugeScore').textContent    = '…';
  $('gaugeScoreSub').style.opacity = '0';
  $('riskLabel').textContent     = 'SCANNING';
  $('riskLabel').style.cssText   = ''; // reset inline overrides
  $('analyzeBtn').disabled       = true;
  $('analyzeBtn').textContent    = '⟳ Scanning…';
  $('reportBtn').disabled        = true;
  $('explanationCard').classList.remove('visible');
  $('signalsPanel').classList.remove('visible');
}

function exitScanningState(callback) {
  const remaining = Math.max(0, 800 - (Date.now() - scanStartTime));
  setTimeout(() => {
    $('gaugeZone').classList.remove('scanning');
    $('analyzeBtn').disabled    = false;
    $('analyzeBtn').textContent = '⟳ Scan Again';
    $('reportBtn').disabled     = false;
    if (callback) callback();
  }, remaining);
}

// ── Display result ───────────────────────────────────────────────────── //

function displayResult(analysis) {
  currentAnalysis = analysis;

  const level      = analysis.risk_level ?? 'Safe';
  const score      = analysis.risk_score ?? 0;
  const isFallback = analysis.is_fallback === true;
  const colors     = LEVEL_COLORS[isFallback ? 'Fallback' : level] ?? LEVEL_COLORS.Default;

  // Gauge arc
  animateGauge(score, colors.gauge);

  // Score counter or special symbol
  if (isFallback) {
    $('gaugeScore').textContent      = '!';
    $('gaugeScoreSub').style.opacity = '0';
  } else {
    $('gaugeScoreSub').style.opacity = '1';
    animateScoreCounter(Math.round(score));
  }

  // Risk label
  const labelEl = $('riskLabel');
  labelEl.textContent       = isFallback ? 'UNVERIFIED' : level.toUpperCase();
  labelEl.style.color       = colors.text;
  labelEl.style.borderColor = colors.border;
  labelEl.style.background  = colors.bg;

  // Explanation card (border-left tinted per risk level)
  $('explanationCard').style.borderLeftColor = colors.border;
  $('explanationText').textContent           = analysis.explanation ?? '';
  $('recommendationText').textContent        = analysis.recommendation ?? '';
  $('explanationCard').classList.add('visible');

  // Signals
  if (!isFallback && analysis.signals && analysis.signals.length > 0) {
    renderSignals(analysis.signals);
  }

  // Footer timestamp
  $('lastCheck').textContent = `Last: ${new Date().toLocaleTimeString()}`;
}

// ── Signal rendering ─────────────────────────────────────────────────── //

function renderSignals(signals) {
  const panel = $('signalsPanel');

  // Remove existing signal rows (keep the title div)
  panel.querySelectorAll('.signal-row').forEach(el => el.remove());

  const ordered = SIGNAL_ORDER
    .map(name => signals.find(s => s.name === name))
    .filter(Boolean);

  const fills = [];

  ordered.forEach((signal) => {
    const color = getScoreColor(signal.score);

    const row      = document.createElement('div');
    row.className  = 'signal-row';

    // Icon
    const iconDiv = document.createElement('div');
    iconDiv.className  = 'signal-icon';
    iconDiv.style.color = color;
    iconDiv.innerHTML  = SIGNAL_ICONS[signal.name] ?? ''; // constant, not user data

    // Info container
    const info    = document.createElement('div');
    info.className = 'signal-info';

    const nameRow = document.createElement('div');
    nameRow.className = 'signal-name-row';

    const nameEl = document.createElement('span');
    nameEl.className   = 'signal-name';
    nameEl.textContent = signal.name; // safe: textContent

    const scoreEl = document.createElement('span');
    scoreEl.className   = 'signal-score';
    scoreEl.style.color = color;
    scoreEl.textContent = Math.round(signal.score);

    nameRow.appendChild(nameEl);
    nameRow.appendChild(scoreEl);

    const track = document.createElement('div');
    track.className = 'signal-bar-track';

    const fill = document.createElement('div');
    fill.className    = 'signal-bar-fill';
    fill.style.background = color;
    fill.style.width  = '0%';

    track.appendChild(fill);
    info.appendChild(nameRow);
    info.appendChild(track);
    row.appendChild(iconDiv);
    row.appendChild(info);
    panel.appendChild(row);

    fills.push({ el: fill, width: signal.score });
  });

  panel.classList.add('visible');

  // Stagger bar animations after the panel slides in
  fills.forEach(({ el, width }, i) => {
    setTimeout(() => { el.style.width = width + '%'; }, 220 + i * 95);
  });
}

// ── Analysis ─────────────────────────────────────────────────────────── //

async function analyzeCurrentPage() {
  const tab = await getCurrentTab();
  if (!tab?.url?.startsWith('http')) return;

  enterScanningState();

  const res = await sendToBackground({ action: 'analyze', url: tab.url });

  if (!res.__error && res.success) {
    exitScanningState(() => displayResult(res.data));
  } else {
    exitScanningState(() => showErrorState());
  }
}

function showErrorState() {
  $('gaugeScore').textContent      = '?';
  $('gaugeScoreSub').style.opacity = '0';
  $('riskLabel').textContent       = 'ERROR';
}

// ── Report phishing ──────────────────────────────────────────────────── //

async function reportPhishing() {
  const tab = await getCurrentTab();
  if (!tab?.url) return;

  const btn     = $('reportBtn');
  btn.disabled  = true;
  btn.textContent = 'Sending…';

  const res = await sendToBackground({
    action:    'report',
    url:       tab.url,
    reason:    'User-reported from popup',
    riskScore: currentAnalysis?.risk_score ?? null,
  });

  if (!res.__error && res.success) {
    btn.textContent = '✓ Reported';
    btn.classList.add('success');
  } else {
    btn.textContent = 'Failed';
    btn.classList.add('failed');
  }
  setTimeout(() => {
    btn.disabled    = false;
    btn.textContent = '⚑ Report Phishing';
    btn.classList.remove('success', 'failed');
  }, 2500);
}

// ── URL display ──────────────────────────────────────────────────────── //

function updateUrlDisplay(tab) {
  $('urlText').textContent = tab?.url ?? 'No active tab';
}

// ── Init ─────────────────────────────────────────────────────────────── //

async function init() {
  const tab = await getCurrentTab();
  updateUrlDisplay(tab);

  checkConnection();
  setInterval(checkConnection, 15000);

  $('analyzeBtn').addEventListener('click', analyzeCurrentPage);
  $('reportBtn').addEventListener('click', reportPhishing);

  // Non-HTTP pages can't be analyzed
  if (!tab?.url?.startsWith('http')) {
    $('gaugeScore').textContent      = '--';
    $('gaugeScoreSub').style.opacity = '0';
    $('riskLabel').textContent       = 'N/A';
    $('analyzeBtn').disabled         = true;
    $('reportBtn').disabled          = true;
    return;
  }

  // Show cached result instantly; fall through to live scan if none
  const cached = await loadCachedResult(tab.url);
  if (cached && !cached.is_fallback) {
    $('gaugeScoreSub').style.opacity = '1';
    displayResult(cached);
  } else {
    analyzeCurrentPage();
  }
}

// ── XSS helper (kept for potential future use) ───────────────────────── //

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

init();
