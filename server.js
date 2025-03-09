const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const bodyParser = require('body-parser');
const { initWebSocketServer, broadcastSensorUpdate } = require('./ws-handler');
const fs = require('fs');

// Create Express app
const app = express();

// Configure HTTPS agent to trust self-signed certificates for internal communication
const agent = new https.Agent({
  rejectUnauthorized: false, // Only for internal container communication
});

// Create HTTP server (for internal use)
let server = http.createServer(app);
console.log('Running WebSocket proxy with HTTP for internal communication');

// Initialize WebSocket server
const wsServer = initWebSocketServer(server);

// Make the broadcast function available to routes
app.locals.broadcastSensorUpdate = broadcastSensorUpdate;

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Set up view engine
app.set('views', path.join(__dirname, 'templates'));
app.set('view engine', 'html');
app.engine('html', require('ejs').renderFile);

// Dashboard route
app.get('/', (req, res) => {
  res.render('dashboard-ws');
});

// Fetch sensor data from yolink_chekt
const API_URL = process.env.API_URL || 'http://yolink_chekt:5000/get_sensor_data';
const FETCH_INTERVAL = parseInt(process.env.FETCH_INTERVAL) || 5000;

async function fetchSensorData() {
  try {
    console.log(`Fetching data from: ${API_URL}`);
    const response = await fetch(API_URL, {
      agent: API_URL.startsWith('https') ? agent : undefined,
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}, Text: ${await response.text()}`);
    }

    const data = await response.json();
    console.log(`Received data for ${data.devices?.length || 0} devices`);
    broadcastSensorUpdate(data.devices || []);
  } catch (error) {
    console.error('Error fetching sensor data:', error.message);

    // Add more detailed error information for debugging
    if (error.cause) {
      console.error('Error cause:', error.cause);
    }
  }
}

// Initial fetch
fetchSensorData().catch(e => console.error('Initial fetch failed:', e.message));

// Start periodic fetching with error handling
setInterval(() => {
  fetchSensorData().catch(e => console.error('Periodic fetch failed:', e.message));
}, FETCH_INTERVAL);

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server available at ws://localhost:${PORT}/ws`);
  console.log(`Dashboard available at http://localhost:${PORT}`);
});

// Handle shutdown
process.on('SIGTERM', () => {
  console.info('SIGTERM signal received.');
  console.log('Closing HTTP server.');
  server.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });
});