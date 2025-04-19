// warning.js
document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const url = params.get('url') || '';

  const displayEl = document.getElementById('url-display');
  try {
    displayEl.textContent = new URL(url).href;
  } catch {
    displayEl.textContent = url;
  }

  // Proceed Anyway → temporary allow, then redirect
  document.getElementById('proceed-btn').addEventListener('click', () => {
    browser.runtime.sendMessage(
      { action: 'tempAllow', url },
      () => {
        console.log('[PhishGuard] Temporarily allowed:', url);
        window.location.href = url;
      }
    );
  });

  // Report false positive
  document.getElementById('report-btn').addEventListener('click', () => {
    browser.runtime.sendMessage(
      { action: 'reportFalsePositive', url },
      () => {
        alert('Thank you. We have received your report.');
        window.close();
      }
    );
  });
});
