const express = require('express');
const router = express.Router();
const { scanUrl } = require('../services/virusTotal');

// Health‑check endpoint
router.get('/', (req, res) => {
  res.json({ status: 'API working' });
});

// URL scan endpoint
router.post('/', async (req, res) => {
  try {
    const { url } = req.body;
    console.log('Received scan request for:', url);

    if (!isValidUrl(url)) {
      console.log('Invalid URL format:', url);
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    const result = await scanUrl(url);
    console.log('Scan result:', result);

    // Return “pass” or “fail” based on the 2‑engine threshold
    res.json({
      result: result.isMalicious ? 'fail' : 'pass',
      details: result
    });
  } catch (error) {
    console.error('Scan error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

function isValidUrl(url) {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

module.exports = router;
