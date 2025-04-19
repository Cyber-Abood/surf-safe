// background.js
// Make sure you’ve loaded webextension-polyfill.js first via manifest.json

console.log('[PhishGuard] background.js loaded');

const SECURITY = {
  ALLOW_LIST_DURATION: 300000,   // 5 minutes
  CACHE_DURATION: 300000,        // 5 minutes cache
  FAILSAFE_BLOCK: true,          // Block if scan fails
  DEBUG: true                    // Enable verbose logging
};

// In-memory caches
const scanCache    = new Map();  // url → { isMalicious, ts }
const pendingScans = new Map();  // url → Promise<boolean>

// ======================== INSTALL & INIT ======================== //
browser.runtime.onInstalled.addListener(async () => {
  console.log('[PhishGuard] Extension installed/updated');
  const defaults = {
    allowList: [],
    settings: {
      strictMode: true,
      scanDelay: 1000,
      enableLogging: SECURITY.DEBUG,
      customApiUrl: 'http://localhost:3000/api/vt-scan'
    }
  };
  await browser.storage.local.set(defaults);
});

// ======================== REQUEST INTERCEPTOR ======================== //
browser.webRequest.onBeforeRequest.addListener(
  async (details) => {
    try {
      const url = details.url;
      if (SECURITY.DEBUG) console.log('[DEBUG] Intercepted URL:', url);

      // Skip extension / internal pages
      if (url.startsWith('moz-extension://') || url.startsWith('about:')) {
        return { cancel: false };
      }

      // Bypass allow-list
      if (await utils.checkAllowList(url)) {
        return { cancel: false };
      }

      // Scan (deduped + cached for navigation)
      const isMalicious = await utils.scanUrl(url);
      if (isMalicious) {
        if (SECURITY.DEBUG) console.log('[ACTION] Blocking URL:', url);
        return { redirectUrl: utils.getWarningPageUrl(url) };
      }
    } catch (err) {
      console.error('[CRITICAL] Interceptor Error:', err);
    }
    return { cancel: false };  // allow by default (or if scan fails and FAILSAFE_BLOCK is false)
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['blocking']
);

// ======================== UTILITIES ======================== //
const utils = {
  async checkAllowList(url) {
    const { allowList = [] } = await browser.storage.local.get('allowList');
    const allowed = allowList.includes(url);
    if (allowed && SECURITY.DEBUG) console.log('[ALLOW-LIST] Bypass for:', url);
    return allowed;
  },

  // Scans a URL for malicious content. If forceFresh is true, ignore cache and pending scans.
  async scanUrl(url, forceFresh = false) {
    // 1) Return cached result (if not forcing a fresh scan)
    const cached = scanCache.get(url);
    if (!forceFresh && cached && Date.now() - cached.ts < SECURITY.CACHE_DURATION) {
      if (SECURITY.DEBUG) console.log('[CACHE] Hit for:', url, cached.isMalicious);
      return Promise.resolve(cached.isMalicious);
    }

    // 2) If a scan is already in-flight for this URL (and not forcing fresh), reuse its promise
    if (!forceFresh && pendingScans.has(url)) {
      if (SECURITY.DEBUG) console.log('[PENDING] Awaiting existing scan for:', url);
      return pendingScans.get(url);
    }

    // 3) Kick off a new scan via the remote API
    const p = (async () => {
      if (SECURITY.DEBUG) console.log('[SCAN] Starting scan for:', url, (forceFresh ? '(fresh scan)' : ''));
      const { settings } = await browser.storage.local.get('settings');
      const endpoint = settings.customApiUrl;

      // Abort the fetch if it takes longer than 10 seconds
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
        signal: controller.signal
      });
      clearTimeout(timer);

      if (!resp.ok) {
        const errorText = await resp.text();
        throw new Error(`API Error ${resp.status}: ${errorText}`);
      }

      const { result, details } = await resp.json();
      if (typeof result !== 'string' || typeof details?.malicious !== 'number') {
        throw new Error('Invalid response format');
      }

      const isMalicious = (result === 'fail') || (details.malicious >= 2);
      // Cache the new scan result with timestamp
      scanCache.set(url, { isMalicious, ts: Date.now() });

      // UI updates: badge and optional notification
      utils.updateBadge(isMalicious);
      utils.notifyScan(url, isMalicious, details);

      return isMalicious;
    })();

    // If this is a real-time navigation scan (not forced by popup), track the pending promise
    if (!forceFresh) {
      pendingScans.set(url, p);
      p.finally(() => {
        if (SECURITY.DEBUG) console.log('[PENDING] Removed pending scan for:', url);
        pendingScans.delete(url);
      });
    }

    return p;
  },

  updateBadge(isMalicious) {
    browser.browserAction.setBadgeText({ text: isMalicious ? '!' : '✓' });
    browser.browserAction.setBadgeBackgroundColor({
      color: isMalicious ? '#c5221f' : '#137333'
    });
  },

  notifyScan(url, isMalicious, details = {}, isError = false) {
    // Only show notifications for debug mode or errors
    if (!SECURITY.DEBUG && !isError) return;
    const title = isError
      ? 'PhishGuard Scan Error'
      : (isMalicious ? 'PhishGuard Alert: Malicious Site' : 'PhishGuard: Site Safe');
    const message = isError
      ? `Failed to scan ${url}`
      : (isMalicious 
          ? `${details.malicious} engines flagged this URL` 
          : `${details.harmless} engines reported this URL safe`);
    browser.notifications.create({
      type: 'basic',
      iconUrl: browser.runtime.getURL('icons/safe48.png'),
      title,
      message
    });
  },

  getWarningPageUrl(url) {
    return browser.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}`);
  }
};

// ======================== MESSAGING ======================== //
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (SECURITY.DEBUG) console.log('[MESSAGE] Received:', request.action);
  switch (request.action) {
    case 'tempAllow':
      // Temporarily allow this URL (adds to allowList and auto-expires)
      handleTempAllow(request.url).then(() => sendResponse({ success: true }));
      return true;

    case 'getScanStatus':
      // Return current cached/pending scan status for a URL
      utils.scanUrl(request.url).then(isMalicious => sendResponse({ isMalicious }))
        .catch(err => {
          if (SECURITY.DEBUG) console.error('[ERROR] getScanStatus failed:', err);
          sendResponse({ isMalicious: SECURITY.FAILSAFE_BLOCK });
        });
      return true;

    case 'scanCustomUrl':
      // Force a fresh scan for the user-provided URL from popup (ignore cache and pending)
      utils.scanUrl(request.url, true)
        .then(isMalicious => sendResponse(isMalicious))
        .catch(err => {
          if (SECURITY.DEBUG) console.error('[ERROR] scanCustomUrl failed:', err);
          sendResponse(SECURITY.FAILSAFE_BLOCK);
        });
      return true;

    default:
      sendResponse({ error: 'Unknown action' });
  }
});

// ======================== TEMP ALLOW ======================== //
async function handleTempAllow(url) {
  // Add URL to in-memory allowList (stored in local storage)
  const { allowList = [] } = await browser.storage.local.get('allowList');
  const updatedList = Array.from(new Set([...allowList, url]));
  await browser.storage.local.set({ allowList: updatedList });
  // Remove the URL from allowList after ALLOW_LIST_DURATION
  setTimeout(async () => {
    const { allowList: currentList = [] } = await browser.storage.local.get('allowList');
    await browser.storage.local.set({
      allowList: currentList.filter(u => u !== url)
    });
    if (SECURITY.DEBUG) console.log('[TEMP ALLOW] Expired:', url);
  }, SECURITY.ALLOW_LIST_DURATION);
}

// ======================== CACHE CLEANUP ======================== //
browser.alarms.create('cacheCleanup', { periodInMinutes: 15 });
browser.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'cacheCleanup') {
    const now = Date.now();
    for (const [url, entry] of scanCache.entries()) {
      if (now - entry.ts > SECURITY.CACHE_DURATION) {
        scanCache.delete(url);
        if (SECURITY.DEBUG) console.log('[CACHE] Removed stale:', url);
      }
    }
  }
});

// ======================== DEBUG LISTENERS ======================== //
if (SECURITY.DEBUG) {
  browser.storage.onChanged.addListener(changes => {
    console.log('[DEBUG] Storage changed:', changes);
  });
  browser.webNavigation.onCompleted.addListener(details => {
    console.log('[DEBUG] Navigation completed:', details.url);
  });
}
