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
  // Check cache first
  if (analysisCache.has(url)) {
    console.log('[FraudGuard] Using cached result for:', url);
    return analysisCache.get(url);
  }

  try {
    console.log('[FraudGuard] Analyzing URL:', url);
    
    const response = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    // Cache the result
    analysisCache.set(url, data);
    
    console.log('[FraudGuard] Analysis result:', data);
    return data;
    
  } catch (error) {
    console.error('[FraudGuard] Error analyzing URL:', error);
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
