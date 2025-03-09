const express = require('express');
const http = require('http');
const https = require('https'); // Added for HTTPS support
const path = require('path');
const bodyParser = require('body-parser');
const { initWebSocketServer, broadcastSensorUpdate } = require('./ws-handler');
const apiRoutes = require('./routes/api');
// Load self-signed certificates
const fs = require('fs');

// Create Express app
const app = express();

// Configure HTTPS agent to trust self-signed certificates
const agent = new https.Agent({
  rejectUnauthorized: false, // Warning: Only for development with self-signed certs
});

// Create HTTP server (will be upgraded to HTTPS if certs are provided)
let server;
if (fs.existsSync('/app/cert.pem') && fs.existsSync('/app/key.pem')) {
  const options = {
    cert: fs.readFileSync('/app/cert.pem'),
    key: fs.readFileSync('/app/key.pem'),
  };
  server = https.createServer(options, app);
  console.log('Running WebSocket proxy with HTTPS');
} else {
  server = http.createServer(app);
  console.log('Running WebSocket proxy with HTTP (certificates not found)');
}

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

// API routes
app.use('/api', apiRoutes);

// Dashboard route
app.get('/', (req, res) => {
  res.render('dashboard-ws');
});

// Fetch sensor data from yolink_chekt
const API_URL = process.env.API_URL || 'https://yolink_chekt:5000/get_sensor_data';
const FETCH_INTERVAL = parseInt(process.env.FETCH_INTERVAL) || 5000;

async function fetchSensorData() {
  try {
    const response = await fetch(API_URL, { agent });
    if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
    const data = await response.json();
    broadcastSensorUpdate(data.sensors || []);
  } catch (error) {
    console.error('Error fetching sensor data:', error.message);
  }
}

// Start periodic fetching
setInterval(fetchSensorData, FETCH_INTERVAL);

// Sample data for development/testing (unchanged)
let sampleSensors = [
  {
    deviceId: "sensor1",
    name: "Front Door",
    type: "door",
    state: "closed",
    battery: 85,
    signal: 4,
    last_seen: new Date().toISOString()
  },
  {
    deviceId: "sensor2",
    name: "Living Room Motion",
    type: "motion",
    state: "normal",
    battery: 90,
    signal: 5,
    last_seen: new Date().toISOString()
  },
  {
    deviceId: "sensor3",
    name: "Kitchen Temperature",
    type: "temperature",
    state: "normal",
    battery: 75,
    signal: 3,
    temperature: 72,
    humidity: 45,
    temperatureUnit: "F",
    last_seen: new Date().toISOString()
  }
];

// Initialize with sample data for development
setTimeout(() => {
  broadcastSensorUpdate(sampleSensors);
}, 1000);

// Simulate updates every 10 seconds for development
if (process.env.NODE_ENV !== 'production') {
  setInterval(() => {
    const index = Math.floor(Math.random() * sampleSensors.length);
    const sensor = sampleSensors[index];
    const states = ['normal', 'alarm', 'open', 'closed'];
    sensor.state = states[Math.floor(Math.random() * states.length)];
    sensor.last_seen = new Date().toISOString();
    broadcastSensorUpdate(sampleSensors);
    console.log(`Updated sensor: ${sensor.name} to state: ${sensor.state}`);
  }, 10000);
}

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
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