// popup.js

document.addEventListener('DOMContentLoaded', () => {
  // --- Elements ---
  const urlInput = document.getElementById('urlInput');
  const checkUrlBtn = document.getElementById('checkUrl');
  const urlLoader = document.getElementById('urlLoader');
  const urlResult = document.getElementById('urlResult');

  // --- Result Display Functions ---
  function showResult(element, message, type) {
    element.innerHTML = message;
    element.className = `result ${type}`;
    element.style.display = 'block';
  }

  function showUrlResult(isMalicious, url) {
    if (isMalicious === 'error') {
      showResult(urlResult, `⚠️ Scan failed. Please try again.`, 'error');
    } else if (isMalicious) {
      showResult(urlResult, `❌ URL appears MALICIOUS!`, 'malicious');
    } else {
      showResult(urlResult, `✅ URL appears SAFE.`, 'safe');
    }
  }

  function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // --- Scan Function (using background.js) ---
  function scanUrlViaBackground(url, loaderElement, callback) {
    loaderElement.style.display = 'block';
    urlResult.textContent = '🔄 Scanning...';
    urlResult.className = 'result';
    urlResult.style.display = 'block';

    browser.runtime.sendMessage(
      { action: 'scanCustomUrl', url: url },
      (isMalicious) => {
        loaderElement.style.display = 'none';

        if (browser.runtime.lastError) {
          console.error("PhishGuard Error:", browser.runtime.lastError.message);
          callback('error', url);
        } else {
          console.log(`PhishGuard Scan result for ${url}:`, isMalicious);
          callback(isMalicious, url);
        }
      }
    );
  }

  // --- Event Listeners ---
  checkUrlBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    urlResult.style.display = 'none'; // Clear previous result
    if (!isValidHttpUrl(url)) {
      showResult(urlResult, '⚠️ Please enter a valid URL (e.g., https://example.com).', 'error');
      return;
    }
    checkUrlBtn.disabled = true;
    scanUrlViaBackground(url, urlLoader, (isMalicious, scannedUrl) => {
      showUrlResult(isMalicious, scannedUrl);
      checkUrlBtn.disabled = false;
    });
  });

  // --- Utility ---
  function isValidHttpUrl(string) {
    let url;
    try {
      url = new URL(string);
    } catch (_) {
      return false;
    }
    return url.protocol === "http:" || url.protocol === "https:";
  }
});
