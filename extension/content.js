/**
 * Content Script for FraudGuard
 * Monitors active tab URL changes and injects warning popup when risk threshold is exceeded
 */

// Track current URL to avoid duplicate checks
let currentUrl = null;
let popupInjected = false;

/**
 * Get the current page URL
 */
function getCurrentUrl() {
  return window.location.href;
}

/**
 * Send URL to background worker for analysis
 */
async function analyzeCurrentUrl() {
  const url = getCurrentUrl();
  
  // Skip if already checked this URL
  if (url === currentUrl) {
    return;
  }
  
  currentUrl = url;
  
  console.log('[FraudGuard Content] Analyzing URL:', url);
  
  // Send message to background worker
  chrome.runtime.sendMessage(
    { action: 'analyze', url: url },
    (response) => {
      if (chrome.runtime.lastError) {
        console.error('[FraudGuard Content] Error:', chrome.runtime.lastError);
        return;
      }
      
      if (response && response.success) {
        handleAnalysisResult(response.data);
      } else {
        console.error('[FraudGuard Content] Analysis failed:', response);
      }
    }
  );
}

/**
 * Handle analysis result and inject popup if needed
 */
function handleAnalysisResult(analysis) {
  console.log('[FraudGuard Content] Analysis result:', analysis);
  
  const riskScore = analysis.risk_score || 0;
  const riskLevel = analysis.risk_level || 'Safe';
  
  // Show popup only for clearly risky sites.
  // Safe sites (0-30) and low Suspicious scores (31-39) don't show popup.
  if (riskScore >= 40) {
    injectWarningPopup(analysis);
  } else {
    // Remove popup if it exists and site is now safe
    removeWarningPopup();
  }
}

/**
 * Inject warning popup into the page
 */
function injectWarningPopup(analysis) {
  // Remove existing popup if any
  removeWarningPopup();
  
  const popup = document.createElement('div');
  popup.id = 'fraudguard-warning-popup';
  popup.innerHTML = `
    <div class="fraudguard-popup-content">
      <div class="fraudguard-popup-header">
        <div class="fraudguard-risk-badge fraudguard-risk-${analysis.risk_level.toLowerCase()}">
          ${analysis.risk_level}
        </div>
        <button class="fraudguard-close-btn" id="fraudguard-close">×</button>
      </div>
      <div class="fraudguard-popup-body">
        <h3 class="fraudguard-title">⚠️ Fraud Warning</h3>
        <div class="fraudguard-score">
          Risk Score: <strong>${analysis.risk_score.toFixed(1)}/100</strong>
        </div>
        <p class="fraudguard-explanation">${analysis.explanation || 'This website shows suspicious characteristics.'}</p>
        <div class="fraudguard-signals">
          ${analysis.signals && analysis.signals.length > 0 ? 
            '<strong>Detected Issues:</strong><ul>' + 
            analysis.signals.map(s => `<li>${s.description}</li>`).join('') + 
            '</ul>' : ''}
        </div>
        <p class="fraudguard-recommendation"><strong>Recommendation:</strong> ${analysis.recommendation}</p>
      </div>
      <div class="fraudguard-popup-actions">
        <button class="fraudguard-btn fraudguard-btn-danger" id="fraudguard-exit">Exit Site</button>
        <button class="fraudguard-btn fraudguard-btn-secondary" id="fraudguard-report">Report Fraud</button>
        <button class="fraudguard-btn fraudguard-btn-primary" id="fraudguard-continue">Continue Anyway</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(popup);
  popupInjected = true;
  
  // Add event listeners
  setupPopupListeners(popup, analysis);
  
  // Animate popup appearance
  setTimeout(() => {
    popup.classList.add('fraudguard-show');
  }, 10);
}

/**
 * Setup event listeners for popup buttons
 */
function setupPopupListeners(popup, analysis) {
  // Close button
  const closeBtn = popup.querySelector('#fraudguard-close');
  closeBtn.addEventListener('click', () => {
    removeWarningPopup();
  });
  
  // Exit Site button
  const exitBtn = popup.querySelector('#fraudguard-exit');
  exitBtn.addEventListener('click', () => {
    window.location.href = 'about:blank';
    removeWarningPopup();
  });
  
  // Report Fraud button
  const reportBtn = popup.querySelector('#fraudguard-report');
  reportBtn.addEventListener('click', () => {
    // Open report page or send to backend
    alert('Thank you for reporting. This helps protect others!');
    // TODO: Implement actual reporting mechanism
    removeWarningPopup();
  });
  
  // Continue Anyway button
  const continueBtn = popup.querySelector('#fraudguard-continue');
  continueBtn.addEventListener('click', () => {
    removeWarningPopup();
    // Store user's decision to continue (optional)
    localStorage.setItem('fraudguard_acknowledged_' + analysis.url, 'true');
  });
  
  // Click outside to close (optional)
  popup.addEventListener('click', (e) => {
    if (e.target === popup) {
      removeWarningPopup();
    }
  });
}

/**
 * Remove warning popup from page
 */
function removeWarningPopup() {
  const popup = document.getElementById('fraudguard-warning-popup');
  if (popup) {
    popup.classList.remove('fraudguard-show');
    setTimeout(() => {
      popup.remove();
      popupInjected = false;
    }, 300);
  }
}

/**
 * Monitor URL changes
 */
function monitorUrlChanges() {
  // Check URL on page load
  analyzeCurrentUrl();
  
  // Monitor for URL changes (SPA navigation)
  let lastUrl = getCurrentUrl();
  setInterval(() => {
    const currentUrl = getCurrentUrl();
    if (currentUrl !== lastUrl) {
      lastUrl = currentUrl;
      analyzeCurrentUrl();
    }
  }, 1000);
}

/**
 * Initialize content script
 */
function init() {
  // Wait for DOM to be ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', monitorUrlChanges);
  } else {
    monitorUrlChanges();
  }
}

// Start monitoring
init();
