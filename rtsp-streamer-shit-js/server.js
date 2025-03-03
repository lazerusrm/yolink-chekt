/**
 * YoLink Dashboard RTSP Streamer
 * Main server file that initializes all components
 */

const express = require('express');
const http = require('http');
const ip = require('ip');
const WebSocketClient = require('./webSocketClient');
const DashboardRenderer = require('./DashboardRenderer');
const RtspStreamer = require('./rtspStreamer');
const OnvifService = require('./onvif-service');
const createApiRouter = require('./apiRouter');

// Configuration from environment variables
const config = {
  dashboardUrl: process.env.DASHBOARD_URL || 'http://websocket-proxy:3000',
  rtspPort: parseInt(process.env.RTSP_PORT, 10) || 8554,
  streamName: process.env.STREAM_NAME || 'yolink-dashboard',
  frameRate: parseInt(process.env.FRAME_RATE, 10) || 1,
  width: parseInt(process.env.WIDTH, 10) || 1920,
  height: parseInt(process.env.HEIGHT, 10) || 1080,
  cycleInterval: parseInt(process.env.CYCLE_INTERVAL, 10) || 10000,
  httpPort: parseInt(process.env.RTSP_API_PORT, 10) || 3001,
  wsPort: parseInt(process.env.WS_PORT, 10) || 9999,
  enableOnvif: process.env.ENABLE_ONVIF !== 'false',
  onvifPort: parseInt(process.env.ONVIF_PORT, 10) || 8555,
  serverIp: process.env.SERVER_IP || ip.address()
};

// Display configuration
console.log('Starting YoLink Dashboard RTSP Streamer with configuration:', config);

// Initialize Express app and HTTP server
const app = express();
const server = http.createServer(app);

// Initialize dashboard renderer
const renderer = new DashboardRenderer({
  width: config.width,
  height: config.height
});

// Connect to the dashboard WebSocket server
const wsUrl = `ws://${config.dashboardUrl.replace(/^https?:\/\//, '')}/ws`;
const wsClient = new WebSocketClient(wsUrl);

// Handle incoming sensor data
wsClient.on('sensors-update', (sensors) => {
  renderer.updateSensors(sensors);
  console.log(`Updated sensors: ${sensors.length}, alarms: ${sensors.filter(s =>
    ['alarm', 'leak', 'motion', 'open'].includes(s?.state)
  ).length}`);
});

// Initialize RTSP streamer
const streamer = new RtspStreamer(config, renderer);
streamer.initialize();

// Page cycling when no alarms
setInterval(() => {
  if (renderer.alarmSensors.length === 0 && renderer.totalPages > 1) {
    renderer.setPage((renderer.currentPage + 1) % renderer.totalPages);
  }
}, config.cycleInterval);

// ONVIF Service
let onvifService = null;
if (config.enableOnvif) {
  onvifService = new OnvifService({
    serverIp: config.serverIp,
    onvifPort: config.onvifPort
  }, server);

  const rtspUrl = `rtsp://${config.serverIp}:${config.rtspPort}/${config.streamName}`;
  onvifService.initialize(rtspUrl);
}

// Create and mount API routes
const apiRouter = createApiRouter(renderer, streamer, config);
app.use(apiRouter);

// Root endpoint
app.get('/', (req, res) => {
  res.send('YoLink RTSP Streamer with ONVIF is running!');
});

// Start HTTP server
server.listen(config.httpPort, () => {
  console.log(`HTTP server running on http://${config.serverIp}:${config.httpPort}`);
});

// Graceful shutdown
function shutdown(signal) {
  console.log(`${signal} received, shutting down...`);

  // Stop RTSP streaming
  if (streamer) {
    streamer.stop();
  }

  // Close WebSocket connection
  if (wsClient) {
    wsClient.close();
  }

  // Stop ONVIF service
  if (onvifService) {
    onvifService.stop();
  }

  // Close HTTP server
  server.close(() => {
    console.log('HTTP server stopped');
    process.exit(0);
  });
}

// Register signal handlers
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));