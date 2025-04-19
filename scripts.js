document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('scanBtn').addEventListener('click', checkURL);
  document.getElementById('qrBtn').addEventListener('click', checkQR);
  document.getElementById('installBtn').addEventListener('click', installExtension);
});

async function checkURL() {
  const urlInput = document.getElementById('urlInput');
  const resultDiv = document.getElementById('urlResult');
  const loader = document.getElementById('urlLoader');

  try {
    loader.style.display = 'block';
    resultDiv.style.display = 'none';

    const response = await fetch('/api/vt-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: urlInput.value })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Unknown error occurred');
    }

    const data = await response.json();
    resultDiv.textContent = data.result === 'pass'
      ? '✅ Safe URL - No phishing detected'
      : `❌ Dangerous - Detected by ${data.details.malicious} engine${data.details.malicious !== 1 ? 's' : ''}!`;
    resultDiv.className = `result ${data.result}`;

  } catch (error) {
    resultDiv.textContent = `Error: ${error.message}`;
    resultDiv.className = 'result error';
  } finally {
    loader.style.display = 'none';
    resultDiv.style.display = 'block';
  }
}

async function checkQR() {
  const fileInput = document.getElementById('qrFile');
  const resultDiv = document.getElementById('qrResult');
  const loader = document.getElementById('qrLoader');

  try {
    if (!fileInput.files[0]) {
      throw new Error('Please select a PNG file');
    }

    loader.style.display = 'block';
    resultDiv.style.display = 'none';

    const formData = new FormData();
    formData.append('qrfile', fileInput.files[0]);

    const response = await fetch('/check-qr', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Unknown error occurred');
    }

    const data = await response.json();
    resultDiv.textContent = data.result === 'pass'
      ? `✅ Safe URL: ${data.url}`
      : `❌ Dangerous URL: ${data.url} (flagged by ${data.details.malicious} engine${data.details.malicious !== 1 ? 's' : ''})`;
    resultDiv.className = `result ${data.result}`;

  } catch (error) {
    resultDiv.textContent = `Error: ${error.message}`;
    resultDiv.className = 'result error';
  } finally {
    loader.style.display = 'none';
    resultDiv.style.display = 'block';
    fileInput.value = '';
  }
}

async function installExtension() {
  const installBtn = document.getElementById('installBtn');
  const originalText = installBtn.textContent;

  try {
    installBtn.disabled = true;
    installBtn.textContent = 'Preparing download...';

    const response = await fetch('/download-extension');
    if (!response.ok) throw new Error(`Server Error: ${response.status}`);

    installBtn.textContent = 'Downloading...';
    const blob = await response.blob();
    const downloadUrl = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = 'PhishGuardExtension.zip';
    document.body.appendChild(a);
    a.click();

    installBtn.textContent = 'Install Complete!';
    document.getElementById('installGuide').style.display = 'block';

    setTimeout(() => {
      URL.revokeObjectURL(downloadUrl);
      installBtn.textContent = originalText;
      installBtn.disabled = false;
    }, 2000);

  } catch (error) {
    console.error('Install failed:', error);
    installBtn.textContent = 'Install Failed - Try Again';
    installBtn.disabled = false;
    setTimeout(() => installBtn.textContent = originalText, 3000);
  }
}

// Register service worker for PWA support
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js')
    .then(() => console.log('Service Worker registered'))
    .catch(err => console.error('SW registration failed:', err));
}
