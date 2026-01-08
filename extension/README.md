# FraudGuard Chrome Extension

Chrome browser extension (Manifest v3) that monitors active tabs and displays fraud warnings for suspicious or dangerous websites.

## Files Overview

- **manifest.json** - Extension configuration (Manifest v3)
- **background.js** - Service worker that communicates with backend API
- **content.js** - Content script that monitors URLs and injects warning popups
- **popup.html** - Extension popup UI
- **popup.js** - Popup functionality and UI logic
- **styles.css** - Styling for injected warning popups
- **icons/** - Extension icons (16x16, 48x48, 128x128)

## Setup Instructions

### 1. Install Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `extension` folder
5. The extension should now be installed

### 2. Configure Backend URL

Before using the extension, make sure your backend server is running (see `../server/README.md`).

The backend URL is configured in `background.js`:
```javascript
const BACKEND_URL = 'http://localhost:8000';
```

For production, update this to your deployed backend URL.

### 3. Test the Extension

1. Make sure the backend server is running on `http://localhost:8000`
2. Visit a website (e.g., `https://example.com`)
3. The extension will automatically analyze the URL
4. If the site is suspicious (risk score > 30), a warning popup will appear
5. Click the extension icon to see the popup UI and manually analyze pages

## How It Works

### Data Flow

1. **Content Script** (`content.js`) monitors the active tab URL
2. When URL changes, it sends the URL to the **Background Worker** (`background.js`)
3. **Background Worker** calls the backend API `/analyze` endpoint
4. Backend returns risk score and analysis details
5. If risk score > 30, **Content Script** injects a warning popup into the page
6. User can interact with popup (Exit Site, Report Fraud, Continue Anyway)

### Risk Thresholds

- **Safe (0-30)**: No popup shown
- **Suspicious (31-70)**: Warning popup shown (yellow/orange)
- **Dangerous (71-100)**: Warning popup shown (red)

### Warning Popup Features

- Risk classification badge (Safe/Suspicious/Dangerous)
- Fraud score display (0-100)
- Explanation text from backend
- Detected issues list
- Recommendation text
- Action buttons:
  - **Exit Site**: Redirects to blank page
  - **Report Fraud**: Reports the site (placeholder)
  - **Continue Anyway**: Dismisses popup

## Development

### Testing Locally

1. Make changes to extension files
2. Go to `chrome://extensions/`
3. Click the refresh icon on the FraudGuard extension card
4. Test on a new tab

### Debugging

- **Background Worker**: Right-click extension icon → "Inspect popup" → Go to "Service Worker" link
- **Content Script**: Open browser DevTools on any webpage → Console tab
- **Popup**: Right-click extension icon → "Inspect popup"

### Console Logs

The extension logs useful information:
- `[FraudGuard]` - Background worker logs
- `[FraudGuard Content]` - Content script logs

## Icons

Place icon files in the `icons/` directory:
- `icon16.png` - 16x16 pixels
- `icon48.png` - 48x48 pixels  
- `icon128.png` - 128x128 pixels

The extension will work without icons, but Chrome will show a default icon.

## Permissions Explained

- **activeTab**: Access to current active tab
- **tabs**: Monitor tab changes
- **storage**: Store analysis cache (future enhancement)
- **host_permissions**: `<all_urls>` - Analyze any website

## Future Enhancements

- Settings page for configuring thresholds
- Report fraud functionality
- Analysis history
- Whitelist trusted domains
- Offline mode with cached results
