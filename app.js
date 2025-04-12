// server/app.js
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { createCanvas, loadImage } = require('canvas');
const jsQR = require('jsqr');
const fs = require('fs');

const scanRouter = require('./routes/scan');
const { scanUrl } = require('./services/virusTotal');

const app = express();
const PORT = process.env.PORT || 3000;

// Debugging logs
console.log('Env Path:', path.resolve(__dirname, '../.env'));
console.log('VT API Key:', process.env.VIRUSTOTAL_API_KEY ? 'Loaded' : 'Missing Key!');

// Security Middleware
app.use(helmet());

// Standard CORS configuration
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://yourdomain.com'
  ]
}));

// ─── Added Manual CORS Headers ───────────────────────────────────────────────
// This ensures Firefox and other clients can POST from anywhere during development
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Content Security Policy
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self';" +
    "script-src 'self' https://apis.virustotal.com;" +
    "style-src 'self' 'unsafe-inline';" +
    "img-src 'self' data:;" +
    "connect-src 'self' https://www.virustotal.com;" +
    "form-action 'self';" +
    "frame-ancestors 'none';"
  );
  next();
});

// Rate Limiting (100 requests per 15 minutes)
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1️⃣ Serve everything in /public (favicon.ico, sw.js, extension zip, etc.)
app.use(express.static(path.join(__dirname, '../public')));

// Request Logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// 2️⃣ API Routes

// VirusTotal scan
app.use('/api/vt-scan', scanRouter);

// QR‑Code scan
const upload = multer({ dest: path.join(__dirname, '../uploads/') });
app.post('/check-qr', upload.single('qrfile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Please upload a PNG file under field name "qrfile"' });
    }

    const image = await loadImage(req.file.path);
    const canvas = createCanvas(image.width, image.height);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(image, 0, 0);

    const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(data, width, height);
    if (!code) throw new Error('No QR code found');

    const vtResult = await scanUrl(code.data);
    res.json({
      result: vtResult.isMalicious ? 'malicious' : 'pass',
      url: code.data,
      details: vtResult
    });
  } catch (error) {
    console.error('QR scan error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Extension download
app.get('/download-extension', (req, res) => {
  const extensionPath = path.join(__dirname, '../public/extension/PhishGuardExtension.zip');
  if (fs.existsSync(extensionPath)) {
    res.download(extensionPath, 'PhishGuardExtension.zip');
  } else {
    res.status(404).json({ error: 'Extension file not found' });
  }
});

// 3️⃣ Root & Error Handling

// Root
app.get('/', (req, res) => {
  res.send('Server is running');
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start Server
app.listen(PORT, () => {
  console.log(`
  🚀 Server running on port ${PORT}
  📡 VT API: ${process.env.VIRUSTOTAL_API_KEY ? 'Connected' : 'Missing Key!'}
  `);
});

module.exports = app;
