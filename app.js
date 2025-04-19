// server/app.js
const path = require('path');

// Load environment variables from .env file first
// Ensure required variables like VIRUSTOTAL_API_KEY and potentially YOUR_PRODUCTION_DOMAIN are set in your .env file
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { createCanvas, loadImage } = require('canvas');
const jsQR = require('jsqr');
const fs = require('fs'); // File System module for cleanup

// Import custom routes and services
const scanRouter = require('./routes/scan'); // Assuming this handles /api/vt-scan correctly
const { scanUrl } = require('./services/virusTotal'); // Assuming this function exists and works

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// --- Initial Debugging & Environment Checks ---
console.log('Environment Path:', path.resolve(__dirname, '../.env'));
console.log('Node Environment:', process.env.NODE_ENV || 'development (default)');
console.log('VT API Key:', process.env.VIRUSTOTAL_API_KEY ? 'Loaded' : 'MISSING! Check .env file.');
if (isProduction && !process.env.YOUR_PRODUCTION_DOMAIN) {
  console.warn('WARNING: Running in production mode but YOUR_PRODUCTION_DOMAIN environment variable is not set. CORS might block frontend access.');
}

// --- Middleware Setup ---

// 1. Security Headers (Enhanced Helmet Configuration)
app.use(
  helmet({
    // Enable HSTS (Strict Transport Security) - forces HTTPS in supporting browsers
    hsts: {
      maxAge: 60 * 60 * 24 * 365, // 1 year in seconds
      includeSubDomains: true, // Apply HSTS to subdomains as well
      preload: true, // Allow submission to HSTS preload lists
    },
    // Prevent clickjacking
    frameguard: {
      action: 'deny',
    },
    // Prevent MIME type sniffing
    noSniff: true,
    // Content Security Policy (Customize further as needed)
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://apis.virustotal.com"], // Allow scripts from self and VT API
        styleSrc: ["'self'", "'unsafe-inline'"], // Allow styles from self and inline styles (remove 'unsafe-inline' if possible)
        imgSrc: ["'self'", "data:"], // Allow images from self and data URIs (for QR codes)
        connectSrc: ["'self'", "https://www.virustotal.com"], // Allow connections to self and VT API
        formAction: ["'self'"], // Allow forms to submit to self
        frameAncestors: ["'none'"], // Disallow embedding in iframes
      },
    },
  })
);


// 2. CORS (Cross-Origin Resource Sharing) - Enhanced and Secure
const allowedOrigins = isProduction
  ? (process.env.YOUR_PRODUCTION_DOMAIN ? process.env.YOUR_PRODUCTION_DOMAIN.split(',') : []) // Allow specific domain(s) in production (comma-separated in ENV var)
  : '*'; // Allow any origin in development

app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST'], // Explicitly allow methods used by your API
  allowedHeaders: ['Content-Type'], // Explicitly allow necessary headers
  credentials: allowedOrigins !== '*', // Set credentials to true only if origin is NOT '*' (not usually needed for this API type)
}));

// 3. Rate Limiting (Enhanced)
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isProduction ? 100 : 500, // Requests per window per IP (stricter in prod)
  message: JSON.stringify({ error: 'Too many requests from this IP, please try again after 15 minutes.' }),
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
}));

// 4. Body Parsing
app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded request bodies

// 5. Serve Static Files (from /public)
app.use(express.static(path.join(__dirname, '../public')));

// 6. Request Logger (Enhanced)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - IP: ${req.ip}`);
  next();
});

// --- File Upload Configuration (Multer - Enhanced) ---
const upload = multer({
  dest: path.join(__dirname, '../uploads/'), // Temporary storage location for uploads
  limits: {
    fileSize: 5 * 1024 * 1024, // Limit file size (e.g., 5MB)
    files: 1, // Limit to 1 file per request
  },
  fileFilter: (req, file, cb) => {
    // Accept only image files based on MIME type
    if (file.mimetype.startsWith('image/')) {
      cb(null, true); // Accept file
    } else {
      // Reject file with a specific error
      cb(new Error('Invalid file type: Only image files (PNG, JPG, etc.) are allowed.'), false);
    }
  },
});

// --- API Routes ---

// 1. VirusTotal URL Scan Route (Using Router)
app.use('/api/vt-scan', scanRouter);

// 2. QR Code Scan Route (Enhanced with Validation and Cleanup)
app.post('/check-qr', upload.single('qrfile'), async (req, res, next) => { // Use next for error delegation
  let uploadedFilePath = req.file ? req.file.path : null; // Store path for cleanup

  try {
    // Check if a file was uploaded (Multer might have rejected it in fileFilter)
    if (!req.file) {
      // This error often originates from the fileFilter or no file being sent
      const err = new Error('Please upload a valid image file (max 5MB) under field name "qrfile".');
      err.status = 400;
      throw err;
    }

    // Load image using canvas
    const image = await loadImage(req.file.path);
    const canvas = createCanvas(image.width, image.height);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(image, 0, 0);

    // Get image data and decode QR code
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
        // Consider adding options if needed, e.g., for inverted QR codes:
        // inversionAttempts: 'dontInvert', // or 'attemptBoth', 'invertFirst'
    });

    // Check if QR code was found
    if (!code || !code.data) {
      throw new Error('No QR code detected in the uploaded image.');
    }

    // --- Validate the QR Code Data ---
    let targetUrl;
    try {
      targetUrl = new URL(code.data); // Throws TypeError if invalid URL format

      // Check for allowed protocols
      if (!['http:', 'https:'].includes(targetUrl.protocol)) {
        throw new Error('Invalid URL protocol in QR code. Only HTTP/HTTPS URLs can be scanned.');
      }

      // Prevent scanning of localhost or private IPs
      const hostname = targetUrl.hostname;
      if (hostname === 'localhost' || hostname === '127.0.0.1' ||
          hostname.match(/^10\.\d+\.\d+\.\d+$/) ||
          hostname.match(/^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/) ||
          hostname.match(/^192\.168\.\d+\.\d+$/)) {
        throw new Error('Scanning of localhost or private network URLs is not permitted.');
      }

    } catch (validationError) {
      // If URL parsing or validation fails, throw a 400 error
      const err = new Error(validationError.message || 'Invalid URL found in QR code.');
      err.status = 400;
      throw err;
    }
    // --- End Validation ---

    // Scan the validated URL using VirusTotal service
    const vtResult = await scanUrl(targetUrl.href); // Use validated URL

    res.json({
      result: vtResult.isMalicious ? 'fail' : 'pass', // Use 'safe' instead of 'pass'
      url: targetUrl.href,
      details: vtResult,
    });

  } catch (error) {
    // Pass error to the global error handler
    next(error);

  } finally {
    // --- Cleanup: Attempt to delete the uploaded file ---
    if (uploadedFilePath) {
      fs.unlink(uploadedFilePath, (unlinkErr) => {
        if (unlinkErr) {
          // Log error if deletion fails, but don't send response here as it might already be sent
          console.error(`Error deleting uploaded file: ${uploadedFilePath}`, unlinkErr);
        } else {
           // console.log(`Successfully deleted uploaded file: ${uploadedFilePath}`); // Optional success log
        }
      });
    }
  }
});

// 3. Extension Download Route
app.get('/download-extension', (req, res, next) => { // Added next for error handling
  const extensionPath = path.join(__dirname, '../public/extension/PhishGuardExtension.zip');

  // Check if file exists before attempting download
  fs.access(extensionPath, fs.constants.R_OK, (err) => { // Check read access
    if (err) {
      console.error('Extension file not found or not readable:', extensionPath);
      return res.status(404).json({ error: 'Extension file not found.' });
    }

    // Proceed with download
    res.download(extensionPath, 'PhishGuardExtension.zip', (downloadErr) => {
      // Handle errors that occur during the file transfer
      if (downloadErr) {
        console.error("Error sending extension file:", downloadErr);
        // If headers haven't been sent yet, send an error response
        // Otherwise, the connection might be broken, just log it.
        if (!res.headersSent) {
           // Pass to global error handler, which will likely send 500
           next(new Error("Could not download the extension file."));
        }
      }
    });
  });
});


// --- Root & Final Middleware ---

// Root path handler
app.get('/', (req, res) => {
  res.send('API Server is running.');
});

// Catch-all for 404 Not Found errors (requests that didn't match any route)
app.use((req, res, next) => {
  res.status(404).json({ error: `Not Found: ${req.method} ${req.originalUrl}` });
});

// --- Global Error Handling Middleware (MUST be last app.use()) ---
app.use((err, req, res, next) => {
  // Log the error internally
  console.error(`[${new Date().toISOString()}] ERROR: ${err.message}`, isProduction ? '' : err.stack); // Less verbose stack in prod logs if desired

  let statusCode = err.status || 500; // Default to 500 if status not set
  let message = err.message || 'An internal server error occurred.';

  // Handle specific error types
  if (err instanceof multer.MulterError) {
    statusCode = 400; // Multer errors are client-side
    if (err.code === 'LIMIT_FILE_SIZE') message = 'File too large. Maximum size allowed is 5MB.';
    else if (err.code === 'LIMIT_FILE_COUNT') message = 'Too many files uploaded. Only one file allowed.';
    // Add other Multer codes if needed
    else message = 'File upload error.';
  } else if (err.message.includes('Invalid file type')) { // From our custom filter
      statusCode = 400;
  } else if (err.message.includes('No QR code detected') ||
             err.message.includes('Invalid URL') || // Covers format, protocol, private IP errors
             err.message.includes('Scanning of localhost')) {
      statusCode = 400; // QR processing/validation errors are client-side
  }
  // Add more specific error checks if needed (e.g., from scanUrl)

  // Sanitize message for production on generic 500 errors
  if (statusCode === 500 && isProduction) {
    message = 'An internal server error occurred. Please try again later.';
  }

  // Send JSON error response
  res.status(statusCode).json({
    error: message,
    // Optionally include error code or other details
    // code: err.code || undefined,
    // Include stack trace ONLY in development mode for debugging
    ...( !isProduction && err.stack && { stack: err.stack }),
  });
});


// --- Start Server ---
app.listen(PORT, () => {
  console.log(`\n🚀 Server listening on port ${PORT}`);
  console.log(`   Mode: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   CORS Allowed Origins: ${allowedOrigins || '(Not Set - Check YOUR_PRODUCTION_DOMAIN in .env for production)'}`);
  console.log(`   Rate Limit: ${isProduction ? 100 : 500} requests/15min per IP`);
  console.log(`   Public files served from: ${path.join(__dirname, '../public')}`);
  console.log(`   Uploads directory: ${path.join(__dirname, '../uploads/')}`);
  console.log(`   Access API root at: http://localhost:${PORT}\n`);
});

// Export the app (useful for testing frameworks like Jest/Supertest)
module.exports = app;
