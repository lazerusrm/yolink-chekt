const express = require('express');
const http = require('http');
const path = require('path');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');

// Create Express app
const app = express();
const server = http.createServer(app);

// Cache for the latest sensor data
let cachedSensorData = [];
let lastFetchTime = 0;

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Set up view engine
app.set('views', path.join(__dirname, 'templates'));
app.set('view engine', 'html');
app.engine('html', require('ejs').renderFile);

// Add simple request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Dashboard route
app.get('/', (req, res) => {
  res.render('dashboard');
});

// API endpoint to get sensor data
app.get('/api/sensors', async (req, res) => {
  try {
    const currentTime = Date.now();
    // Only fetch new data if it's been more than 2 seconds since last fetch
    if (currentTime - lastFetchTime > 2000) {
      const newData = await fetchSensorData();
      if (newData) {
        cachedSensorData = newData;
        lastFetchTime = currentTime;
      }
    }

    res.json({
      sensors: cachedSensorData,
      timestamp: lastFetchTime
    });
  } catch (error) {
    console.error('Error in /api/sensors:', error);
    res.status(500).json({
      error: 'Failed to retrieve sensor data',
      message: error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    lastDataTimestamp: lastFetchTime ? new Date(lastFetchTime).toISOString() : null,
    sensorCount: cachedSensorData.length
  });
});

// Force refresh endpoint
app.post('/api/refresh', async (req, res) => {
  try {
    const newData = await fetchSensorData();
    if (newData) {
      cachedSensorData = newData;
      lastFetchTime = Date.now();
      res.json({
        success: true,
        message: 'Data refreshed',
        count: cachedSensorData.length
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'No data available'
      });
    }
  } catch (error) {
    console.error('Error refreshing data:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Fetch sensor data from yolink_chekt
const API_URL = process.env.API_URL || 'http://yolink_chekt:5000/get_sensor_data';

async function fetchSensorData() {
  try {
    console.log(`Fetching data from: ${API_URL}`);

    // Create a timeout for the fetch
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(API_URL, {
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-Forwarded-Proto': 'https',    // Add this to prevent HTTPS redirect
        'X-Internal-Request': 'true'     // Add this for internal request identification
      },
      signal: controller.signal,
      // Add this to prevent redirects - important!
      redirect: 'manual'
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`);
    }

    const data = await response.json();
    console.log(`Received data for ${data.devices?.length || 0} devices`);

    return data.devices || [];
  } catch (error) {
    console.error('Error fetching sensor data:', error.message);
    return null;
  }
}

// Periodically update data in the background
const FETCH_INTERVAL = parseInt(process.env.FETCH_INTERVAL) || 5000;
const updateInterval = setInterval(async () => {
  try {
    const newData = await fetchSensorData();
    if (newData) {
      cachedSensorData = newData;
      lastFetchTime = Date.now();
    }
  } catch (error) {
    console.error('Error in background update:', error);
  }
}, FETCH_INTERVAL);

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Dashboard available at http://localhost:${PORT}`);
  console.log(`API endpoint available at http://localhost:${PORT}/api/sensors`);
});

// Handle shutdown
process.on('SIGTERM', () => {
  console.info('SIGTERM signal received.');
  clearInterval(updateInterval);
  console.log('Closing HTTP server.');
  server.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });
});