// server/services/virusTotal.js
const axios = require('axios');
const qs = require('qs');
require('dotenv').config();

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;

async function scanUrl(url) {
  if (!VT_API_KEY) {
    throw new Error("VIRUSTOTAL_API_KEY is missing in the environment variables.");
  }

  try {
    const data = qs.stringify({ url });

    // Submit the URL for scanning
    const scanRes = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      data,
      {
        headers: {
          'x-apikey': VT_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const analysisId = scanRes.data.data.id;

    // Wait a bit to let analysis complete (optional improvement)
    await new Promise(res => setTimeout(res, 2000)); // wait 2 seconds

    // Get the scan report
    const reportRes = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { 'x-apikey': VT_API_KEY }
      }
    );

    const stats = reportRes.data.data.attributes.stats;

    // 👇 Log the stats for debugging
    console.log('🔍 VirusTotal Stats:', stats);

    return {
      isMalicious: stats.malicious >= 2,
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undetected: stats.undetected,
      scan_date: new Date(reportRes.data.data.attributes.date * 1000).toISOString(),
      permalink: `https://www.virustotal.com/gui/url/${analysisId}`
    };

  } catch (error) {
    const errMsg = error.response ? JSON.stringify(error.response.data) : error.message;
    throw new Error(`VT Scan Failed: ${errMsg}`);
  }
}

module.exports = { scanUrl };
