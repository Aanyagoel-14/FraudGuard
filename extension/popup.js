/**
 * Popup Script for FraudGuard Extension
 * Handles UI interactions in the extension popup
 */

/**
 * Get the current active tab
 */
async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

/**
 * Update popup UI with current tab information
 */
async function updatePopup() {
  const tab = await getCurrentTab();
  const urlElement = document.getElementById('currentUrl');
  const statusElement = document.getElementById('status');
  
  if (tab && tab.url) {
    urlElement.textContent = tab.url;
    
    // Check if URL is valid (not chrome:// or extension://)
    if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      statusElement.className = 'status active';
      statusElement.querySelector('.status-text').textContent = '✓ Monitoring active';
    } else {
      statusElement.className = 'status';
      statusElement.querySelector('.status-text').textContent = 'Cannot analyze this page';
    }
  } else {
    urlElement.textContent = 'No active tab found';
    statusElement.className = 'status';
    statusElement.querySelector('.status-text').textContent = 'No active tab';
  }
}

/**
 * Analyze current page
 */
async function analyzeCurrentPage() {
  const tab = await getCurrentTab();
  
  if (!tab || !tab.url) {
    alert('No active tab found');
    return;
  }
  
  if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) {
    alert('Cannot analyze this type of page');
    return;
  }
  
  // Update status
  const statusElement = document.getElementById('status');
  statusElement.className = 'status';
  statusElement.querySelector('.status-text').textContent = 'Analyzing...';
  
  // Send message to background worker
  chrome.runtime.sendMessage(
    { action: 'analyze', url: tab.url },
    (response) => {
      if (chrome.runtime.lastError) {
        statusElement.className = 'status';
        statusElement.querySelector('.status-text').textContent = 'Error: ' + chrome.runtime.lastError.message;
        return;
      }
      
      if (response && response.success) {
        displayAnalysisResult(response.data);
      } else {
        statusElement.className = 'status';
        statusElement.querySelector('.status-text').textContent = 'Analysis failed';
      }
    }
  );
}

/**
 * Display analysis result in popup
 */
function displayAnalysisResult(analysis) {
  const statusElement = document.getElementById('status');
  const riskLevel = analysis.risk_level || 'Safe';
  const riskScore = analysis.risk_score || 0;
  
  // Update status based on risk level
  statusElement.className = 'status';
  
  let statusText = '';
  let statusColor = '';
  
  if (riskLevel === 'Safe') {
    statusColor = '#4caf50';
    statusText = `✓ Safe (Score: ${riskScore.toFixed(1)})`;
  } else if (riskLevel === 'Suspicious') {
    statusColor = '#ff9800';
    statusText = `⚠ Suspicious (Score: ${riskScore.toFixed(1)})`;
  } else {
    statusColor = '#f44336';
    statusText = `⚠️ Dangerous (Score: ${riskScore.toFixed(1)})`;
  }
  
  statusElement.style.background = statusColor;
  statusElement.style.color = 'white';
  statusElement.querySelector('.status-text').textContent = statusText;
  
  // Show explanation if available
  if (analysis.explanation) {
    const explanation = document.createElement('div');
    explanation.style.marginTop = '10px';
    explanation.style.fontSize = '12px';
    explanation.style.opacity = '0.9';
    explanation.textContent = analysis.explanation;
    
    // Remove existing explanation if any
    const existing = statusElement.querySelector('.explanation');
    if (existing) existing.remove();
    
    explanation.className = 'explanation';
    statusElement.appendChild(explanation);
  }
}

/**
 * Open settings (placeholder)
 */
function openSettings() {
  // TODO: Implement settings page
  alert('Settings coming soon!');
}

/**
 * Initialize popup
 */
async function init() {
  // Update popup on load
  await updatePopup();
  
  // Setup event listeners
  document.getElementById('analyzeBtn').addEventListener('click', analyzeCurrentPage);
  document.getElementById('settingsBtn').addEventListener('click', openSettings);
  
  // Update popup every 2 seconds to reflect tab changes
  setInterval(updatePopup, 2000);
}

// Initialize when popup opens
init();
