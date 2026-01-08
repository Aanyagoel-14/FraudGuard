# FraudGuard Testing Guide - Step by Step

## ✅ Step 1: Start the Backend Server

**Open a terminal and run these commands:**

```bash
# Navigate to project root (IMPORTANT!)
cd /Users/aanyagoel/Desktop/FraudGuard

# Verify you're in the right place
pwd
# Should show: /Users/aanyagoel/Desktop/FraudGuard

# Install dependencies (if not done already)
pip install -r server/requirements.txt

# Start the server (from project root!)
uvicorn server.main:app --reload --host 0.0.0.0 --port 8000
```

**✅ You should see:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

**⚠️ Keep this terminal open!** Don't close it.

---

## ✅ Step 2: Verify Backend is Working

**Open your web browser and test:**

1. **Health Check:**
   - Go to: `http://localhost:8000/health`
   - Should show: `{"status":"healthy"}`

2. **API Docs:**
   - Go to: `http://localhost:8000/docs`
   - Should show Swagger UI

3. **Test API with curl (in a NEW terminal):**
   ```bash
   curl -X POST "http://localhost:8000/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
   ```
   - Should return JSON with `risk_score`, `risk_level`, etc.

**If any of these fail, the backend isn't running correctly. Fix that first!**

---

## ✅ Step 3: Load Extension in Chrome

1. Open Chrome
2. Go to: `chrome://extensions/`
3. Enable **"Developer mode"** (toggle in top-right)
4. Click **"Load unpacked"**
5. Navigate to: `/Users/aanyagoel/Desktop/FraudGuard/extension`
6. Click **"Select"**

**✅ Extension should appear with no errors (yet)**

---

## ✅ Step 4: Verify Extension Configuration

**Check `extension/background.js` line 7:**
```javascript
const BACKEND_URL = 'http://localhost:8000';
```

This should match your backend URL.

---

## ✅ Step 5: Test the Extension

1. **Clear old errors:**
   - In `chrome://extensions/`
   - Click **"Errors"** on FraudGuard card
   - Click **"Clear all"**

2. **Open Service Worker Console:**
   - In `chrome://extensions/`
   - Find FraudGuard card
   - Click **"service worker"** link (under "Inspect views")
   - A DevTools window opens - this is your background worker console

3. **Visit a test website:**
   - Open a new tab
   - Go to: `https://example.com`
   - Wait 2-3 seconds

4. **Check the Service Worker Console:**
   - You should see logs like:
     ```
     [FraudGuard] Analyzing URL: https://example.com
     [FraudGuard] Analysis result: { risk_score: ..., risk_level: ... }
     ```

5. **If you see "Failed to fetch":**
   - **Check backend is running** (Step 1)
   - **Check backend URL** in browser: `http://localhost:8000/health`
   - **Reload extension**: Click reload icon on FraudGuard card

---

## ✅ Step 6: Test Suspicious URL (Should Show Popup)

1. **Visit a suspicious URL:**
   - Go to: `https://example.com/secure-login/verify-account`
   - This has phishing keywords → should trigger popup

2. **You should see:**
   - A warning popup injected on the page
   - Risk level: "Suspicious" or "Dangerous"
   - Risk score displayed
   - Action buttons (Exit Site, Report Fraud, Continue Anyway)

---

## 🔧 Troubleshooting

### Error: "Failed to fetch"
- ✅ Backend not running → Go to Step 1
- ✅ Wrong URL → Check `background.js` line 7
- ✅ CORS issue → Already fixed in `config.py`

### Error: "ModuleNotFoundError: No module named 'server'"
- ✅ Running from wrong directory → Must run from project root!
- ✅ Use: `cd /Users/aanyagoel/Desktop/FraudGuard` first

### Extension shows errors but backend works
- ✅ Reload extension: Click reload icon
- ✅ Clear errors: Click "Clear all" in Errors panel
- ✅ Check service worker console for detailed errors

### Popup doesn't appear
- ✅ Check risk score > 40 (popup threshold)
- ✅ Check browser console (F12) for content script errors
- ✅ Try a more suspicious URL with keywords

---

## 📝 Quick Test URLs

**Safe (no popup):**
- `https://google.com`
- `https://github.com`

**Suspicious (should show popup):**
- `https://example.com/secure-login/verify-account`
- `http://example.com` (no HTTPS)

**Very Suspicious (definitely popup):**
- `https://secure-login-paypa1.com/login` (if domain exists)
- `https://verify-account-chase.com` (if domain exists)

---

## ✅ Success Indicators

You'll know it's working when:
1. ✅ Backend terminal shows: `INFO: 127.0.0.1:xxxxx - "POST /analyze HTTP/1.1" 200 OK`
2. ✅ Service worker console shows analysis results (no errors)
3. ✅ Suspicious URLs show warning popup on page
4. ✅ Extension popup (click icon) shows current page status
