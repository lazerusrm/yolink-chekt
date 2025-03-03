const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { createCanvas } = require('canvas');
const Stream = require('node-rtsp-stream');
const fs = require('fs');
const path = require('path');
const ip = require('ip');
const OnvifService = require('./onvif-service');

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
  serverIp: process.env.SERVER_IP === 'auto' ? ip.address() : process.env.SERVER_IP || ip.address()
};

// Warn if using auto-detected IP in Docker
if (process.env.SERVER_IP === 'auto') {
  console.warn('Using auto-detected IP. In Docker, set SERVER_IP to the host\'s IP for external access.');
}

// Canvas setup
const canvas = createCanvas(config.width, config.height);
const ctx = canvas.getContext('2d');

// Sensor state
let sensorData = [];
let alarmSensors = [];
let currentPage = 0;
let totalPages = 1;

// WebSocket connection to dashboard
const wsUrl = `ws://${config.dashboardUrl.replace(/^https?:\/\//, '')}/ws`;
function connectToDashboard() {
  const ws = new WebSocket(wsUrl);
  ws.on('open', () => console.log('Connected to dashboard WebSocket'));
  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());
      console.log('Received WebSocket message:', message);
      if (message.type === 'sensors-update') {
        sensorData = message.sensors || [];
        alarmSensors = sensorData.filter(s => ['alarm', 'leak', 'motion', 'open'].includes(s.state));
        totalPages = Math.max(1, Math.ceil(sensorData.length / 12));
      }
    } catch (err) {
      console.error('Error processing dashboard message:', err);
    }
  });
  ws.on('close', () => {
    console.log('Dashboard WebSocket closed, reconnecting in 5 seconds...');
    setTimeout(connectToDashboard, 5000);
  });
  ws.on('error', (err) => console.error('Dashboard WebSocket error:', err));
}
connectToDashboard();

// Render dashboard to canvas
function renderDashboard() {
  ctx.fillStyle = '#1e1e1e';
  ctx.fillRect(0, 0, config.width, config.height);

  if (alarmSensors.length > 0) {
    ctx.fillStyle = '#ff0000';
    ctx.fillRect(0, 0, config.width, config.height);
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 36px Arial';
    ctx.fillText('⚠️ ALARM SENSORS DETECTED ⚠️', 20, 40);
    let y = 80;
    alarmSensors.slice(0, 12).forEach(sensor => {
      ctx.fillText(`${sensor.name}: ${sensor.state.toUpperCase()}`, 20, y);
      y += 40;
    });
  } else {
    ctx.fillStyle = '#ffffff';
    ctx.font = '20px Arial';
    ctx.fillText(`Page ${currentPage + 1} of ${totalPages}`, 20, 40);
    const sensorsPerPage = 12;
    const start = currentPage * sensorsPerPage;
    const end = start + sensorsPerPage;
    let y = 80;
    sensorData.slice(start, end).forEach(sensor => {
      ctx.fillText(`${sensor.name}: ${sensor.state}`, 20, y);
      y += 30;
    });
  }

  ctx.fillStyle = '#ffffff';
  ctx.font = '14px Arial';
  const timestamp = new Date().toLocaleString();
  ctx.fillText(`Last Updated: ${timestamp}`, 10, config.height - 20);

  return canvas.toBuffer('image/jpeg');
}

// RTSP Stream setup
const streamDir = '/tmp/streams';
if (!fs.existsSync(streamDir)) fs.mkdirSync(streamDir, { recursive: true });
const imagePath = path.join(streamDir, 'dashboard.jpg');

const streamOptions = {
  name: config.streamName,
  streamUrl: `rtsp://${config.serverIp}:${config.rtspPort}/${config.streamName}`,
  port: config.wsPort, // WebSocket port for RTSP clients
  ffmpegOptions: {
    '-re': '',
    '-f': 'image2',
    '-loop': '1',
    '-r': String(config.frameRate),
    '-i': imagePath,
    '-c:v': 'libx264',
    '-preset': 'ultrafast',
    '-tune': 'zerolatency',
    '-pix_fmt': 'yuv420p',
    '-b:v': '2M',
    '-bufsize': '2M',
    '-maxrate': '2M',
    '-g': String(config.frameRate * 2),
    '-f': 'rtsp',
    '-rtsp_transport': 'tcp'
  }
};

let rtspStream;
try {
  rtspStream = new Stream(streamOptions);
  console.log(`RTSP stream started: ${streamOptions.streamUrl}`);
} catch (err) {
  console.error('Failed to start RTSP stream:', err);
}

function updateFrame() {
  try {
    const frame = renderDashboard();
    fs.writeFileSync(imagePath, frame);
    console.log('Frame updated');
  } catch (err) {
    console.error('Error updating frame:', err);
  }
  setTimeout(updateFrame, 1000 / config.frameRate);
}
updateFrame();

// Cycle pages when no alarms
setInterval(() => {
  if (alarmSensors.length === 0 && totalPages > 1) {
    currentPage = (currentPage + 1) % totalPages;
  }
}, config.cycleInterval);

// Express app and HTTP server
const app = express();
const server = http.createServer(app);

// ONVIF Service
let onvifService = null;
if (config.enableOnvif) {
  onvifService = new OnvifService(config, server);
  onvifService.initialize(streamOptions.streamUrl);
}

// Express API endpoints
app.get('/', (req, res) => res.send('YoLink RTSP Streamer with ONVIF is running!'));

app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    sensors: { total: sensorData.length, alarmsActive: alarmSensors.length },
    stream: {
      rtspUrl: streamOptions.streamUrl,
      onvifUrl: config.enableOnvif ? `onvif://${config.serverIp}:${config.httpPort}` : null,
      frameRate: config.frameRate,
      resolution: `${config.width}x${config.height}`,
      currentPage: currentPage + 1,
      totalPages
    },
    lastUpdate: new Date().toISOString()
  });
});

app.get('/snapshot', (req, res) => {
  try {
    const frame = renderDashboard();
    res.contentType('image/jpeg');
    res.send(frame);
  } catch (err) {
    console.error('Error generating snapshot:', err);
    res.status(500).send('Error generating snapshot');
  }
});

// Start HTTP server
server.listen(config.httpPort, () => {
  console.log(`HTTP server running on http://${config.serverIp}:${config.httpPort}`);
});

// Graceful shutdown
function shutdown(signal) {
  console.log(`${signal} received, shutting down...`);
  if (rtspStream) {
    rtspStream.stop();
    console.log('RTSP stream stopped');
  }
  if (onvifService) onvifService.stop();
  server.close(() => {
    console.log('HTTP server stopped');
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));