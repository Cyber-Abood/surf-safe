// server/services/virusTotal.js
const axios = require('axios');
const qs = require('qs');
const crypto = require('crypto');
require('dotenv').config();

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const POLL_INTERVAL = 3000;        // 3 seconds
const MAX_POLL_ATTEMPTS = 4;       // maximum polling attempts
const CACHE_TTL = 60 * 60 * 1000;  // 1 hour in milliseconds
const MALICIOUS_THRESHOLD = 2;     // engines required to consider URL malicious

// In-memory cache for URL scan results
const scanCache = new Map();
// Periodically clean up expired cache entries
setInterval(() => {
  const now = Date.now();
  for (const [url, entry] of scanCache.entries()) {
    if (now - entry.timestamp > CACHE_TTL) {
      scanCache.delete(url);
    }
  }
}, CACHE_TTL);

// Main function to scan a URL (or fetch its VT analysis)
async function scanUrl(url) {
  if (!VT_API_KEY) {
    throw new Error('VIRUSTOTAL_API_KEY is missing in environment variables');
  }
  // Input validation
  if (typeof url !== 'string' || !isValidUrl(url)) {
    throw new Error('Invalid URL format');
  }

  // Return cached result if available (within 1 hour)
  const cached = scanCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    console.log(`⚡ Using cached VirusTotal result for: ${url}`);
    return cached.result;
  }

  try {
    // 1. Check if URL already has a VirusTotal report
    const urlId = toVirusTotalID(url);
    let vtData = null;
    try {
      const reportRes = await axios.get(
        `https://www.virustotal.com/api/v3/urls/${urlId}`,
        { headers: { 'x-apikey': VT_API_KEY }, timeout: 10000 }
      );
      vtData = reportRes.data.data;  // existing report found
      console.log(`ℹ️ Found existing VT analysis for URL: ${url}`);
    } catch (err) {
      if (err.response && err.response.status === 404) {
        // No existing report (URL not in VirusTotal DB)
        console.log(`🔍 No VT record for URL, submitting new scan: ${url}`);
      } else {
        // Other error (network issue, API down, etc.)
        throw err;  // will be caught by outer try-catch
      }
    }

    // 2. If no existing data, submit URL for analysis
    let analysisId;
    if (!vtData) {
      const submitRes = await axios.post(
        'https://www.virustotal.com/api/v3/urls',
        qs.stringify({ url }),  // form-urlencoded body
        {
          headers: {
            'x-apikey': VT_API_KEY,
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 10000
        }
      );
      const data = submitRes.data.data;
      if (!data?.id) {
        throw new Error('Unexpected response from VirusTotal (no analysis ID)');
      }
      analysisId = data.id;
      console.log(`🚀 URL submitted to VirusTotal (analysis ID: ${analysisId})`);

      // Poll the analysis status until it's done or until max attempts
      let attempts = 0;
      let status = 'queued';
      while (attempts < MAX_POLL_ATTEMPTS && status !== 'completed') {
        attempts++;
        // Wait for POLL_INTERVAL before next status check
        await new Promise(res => setTimeout(res, POLL_INTERVAL));
        const statusRes = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          { headers: { 'x-apikey': VT_API_KEY }, timeout: 10000 }
        );
        const analysisData = statusRes.data.data;
        status = analysisData.attributes.status;
        console.log(`⏳ Poll attempt ${attempts}: status = ${status}`);
        if (status === 'completed') {
          vtData = analysisData;  // we will use stats from this completed analysis
          break;
        }
      }
      if (!vtData || vtData.attributes.status !== 'completed') {
        console.warn('⚠️ VirusTotal analysis not completed within time limit');
        // Prepare a fallback result indicating no definitive outcome (potential future ML use)
        const fallbackResult = {
          isMalicious: false,
          malicious: 0,
          suspicious: 0,
          harmless: 0,
          undetected: 0,
          scan_date: new Date().toISOString(),
          permalink: createPermalink(url)
        };
        // Cache the fallback result (to avoid re-triggering scan immediately)
        scanCache.set(url, { result: fallbackResult, timestamp: Date.now() });
        return fallbackResult;
      }
    }

    // 3. Process VirusTotal data (either from existing report or completed analysis)
    const stats = extractStats(vtData);
    const scanDate = vtData.attributes.last_analysis_date ?? vtData.attributes.date;  // use appropriate date field
    const result = {
      isMalicious: stats.malicious >= MALICIOUS_THRESHOLD,
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undetected: stats.undetected,
      scan_date: scanDate 
        ? new Date(scanDate * 1000).toISOString() 
        : new Date().toISOString(),
      permalink: createPermalink(url)
    };

    // 4. Cache the result for future requests
    scanCache.set(url, { result, timestamp: Date.now() });
    console.log(`✅ VirusTotal scan complete for ${url} (Malicious engines: ${stats.malicious})`);
    return result;

  } catch (error) {
    // Handle specific VirusTotal API errors
    if (error.response?.status === 409) {
      // 409 Conflict: analysis for this URL is already in progress or recently done
      console.warn('⚠️ Received 409 Conflict from VT API, fetching existing analysis data');
      const existingId = error.response.data.meta?.url_info?.id;
      if (existingId) {
        // Retrieve the existing report using the provided URL ID
        const reportRes = await axios.get(
          `https://www.virustotal.com/api/v3/urls/${existingId}`,
          { headers: { 'x-apikey': VT_API_KEY }, timeout: 10000 }
        );
        const attributes = reportRes.data.data.attributes;
        const stats = {
          malicious: attributes.last_analysis_stats.malicious || 0,
          suspicious: attributes.last_analysis_stats.suspicious || 0,
          harmless: attributes.last_analysis_stats.harmless || 0,
          undetected: attributes.last_analysis_stats.undetected || 0
        };
        const conflictResult = {
          isMalicious: stats.malicious >= MALICIOUS_THRESHOLD,
          malicious: stats.malicious,
          suspicious: stats.suspicious,
          harmless: stats.harmless,
          undetected: stats.undetected,
          scan_date: attributes.last_analysis_date 
            ? new Date(attributes.last_analysis_date * 1000).toISOString()
            : new Date().toISOString(),
          permalink: createPermalink(url)
        };
        // Cache and return the conflict-resolved result
        scanCache.set(url, { result: conflictResult, timestamp: Date.now() });
        return conflictResult;
      }
    }

    // General error handling and logging
    const status = error.response?.status;
    const errMsg = error.response?.data?.error?.message || error.message;
    console.error(`❌ VirusTotal scan failed (${status || 'Network'}): ${errMsg}`);
    throw new Error(`VirusTotal scan failed: ${errMsg}`);
  }
}

// Helper: Validate URL format (using WHATWG URL)
function isValidUrl(str) {
  try {
    new URL(str);
    return true;
  } catch {
    return false;
  }
}

// Helper: Compute URL-safe base64 ID required by VirusTotal API&#8203;:contentReference[oaicite:7]{index=7}
function toVirusTotalID(url) {
  const base64 = Buffer.from(url).toString('base64');
  // Make it URL-safe: replace '+' -> '-', '/' -> '_' and strip '=' padding
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Helper: Create a permalink to VirusTotal’s GUI for this URL
function createPermalink(url) {
  // VirusTotal GUI expects the URL's SHA-256 hash as identifier in the URL
  const urlHash = crypto.createHash('sha256').update(url).digest('hex');
  return `https://www.virustotal.com/gui/url/${urlHash}/detection`;
}

// Helper: Extract analysis stats (malicious, suspicious, harmless, undetected) from VT data
function extractStats(vtData) {
  let stats = {};
  if (vtData.attributes.last_analysis_stats) {
    // Case for existing URL report object
    stats = vtData.attributes.last_analysis_stats;
  } else if (vtData.attributes.stats) {
    // Case for analysis object (from /analyses endpoint)
    stats = vtData.attributes.stats;
  }
  return {
    malicious: Number(stats.malicious) || 0,
    suspicious: Number(stats.suspicious) || 0,
    harmless: Number(stats.harmless) || 0,
    undetected: Number(stats.undetected) || 0
  };
}

module.exports = { scanUrl };
