/**
 * YoLink Dashboard RTSP Streaming Server
 * Creates an RTSP stream of the YoLink dashboard with ONVIF support
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { createCanvas } = require('canvas');
const ffmpeg = require('fluent-ffmpeg');
const Stream = require('node-rtsp-stream');
const fs = require('fs');
const ip = require('ip');
const path = require('path');
const OnvifService = require('./onvif-service');

// Configuration
const config = {
  // Dashboard connection
  dashboardUrl: process.env.DASHBOARD_URL || 'http://dashboard:3000',

  // RTSP streaming
  rtspPort: parseInt(process.env.RTSP_PORT || '8554'),
  streamName: process.env.STREAM_NAME || 'yolink-dashboard',
  frameRate: parseInt(process.env.FRAME_RATE || '1'),

  // Rendering
  width: parseInt(process.env.WIDTH || '1920'),
  height: parseInt(process.env.HEIGHT || '1080'),
  cycleInterval: parseInt(process.env.CYCLE_INTERVAL || '10000'), // 10 seconds

  // ONVIF
  onvifPort: parseInt(process.env.ONVIF_PORT || '8555'),
  enableOnvif: process.env.ENABLE_ONVIF !== 'false', // Enabled by default
  serverIp: process.env.SERVER_IP || ip.address()
};

// Initialize Express app
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Store sensor data
let sensorData = [];
let alarmSensors = [];
let currentPage = 0;
let totalPages = 1;
let lastFrameTime = Date.now();
let rtspStream = null;
let onvifService = null;

// Canvas setup for rendering the dashboard
const canvas = createCanvas(config.width, config.height);
const ctx = canvas.getContext('2d');

// Connect to the dashboard WebSocket to get real-time sensor data
function connectToDashboard() {
  const wsUrl = `ws://${config.dashboardUrl.replace(/^https?:\/\//, '')}/ws`;
  console.log(`Connecting to dashboard WebSocket: ${wsUrl}`);

  const ws = new WebSocket(wsUrl);

  ws.on('open', () => {
    console.log('Connected to dashboard WebSocket');
  });

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());
      if (message.type === 'sensors-update') {
        sensorData = message.sensors;
        // Identify sensors in alarm state
        alarmSensors = sensorData.filter(sensor =>
          sensor.state === 'alarm' ||
          sensor.state === 'leak' ||
          sensor.state === 'motion' ||
          sensor.state === 'open'
        );

        // Calculate total pages needed
        const sensorsPerPage = 12; // Approx 12 sensors per page in a 4x3 grid
        totalPages = Math.max(1, Math.ceil(sensorData.length / sensorsPerPage));
      }
    } catch (err) {
      console.error('Error processing dashboard message:', err);
    }
  });

  ws.on('close', () => {
    console.log('Dashboard WebSocket closed, reconnecting in 5 seconds...');
    setTimeout(connectToDashboard, 5000);
  });

  ws.on('error', (err) => {
    console.error('Dashboard WebSocket error:', err);
    setTimeout(connectToDashboard, 5000);
  });
}

// Function to render the dashboard to canvas
function renderDashboard() {
  // Clear canvas
  ctx.fillStyle = '#1e1e1e';
  ctx.fillRect(0, 0, config.width, config.height);

  // If there are alarm sensors, show them full screen
  if (alarmSensors.length > 0) {
    // Calculate how many alarms we can fit on screen
    const columns = Math.floor(Math.sqrt(alarmSensors.length)) || 1;
    const rows = Math.ceil(alarmSensors.length / columns);
    const width = config.width / columns;
    const height = config.height / rows;

    // Draw alarm sensors
    alarmSensors.forEach((sensor, index) => {
      const x = (index % columns) * width;
      const y = Math.floor(index / columns) * height;

      // Draw sensor box with red background
      ctx.fillStyle = '#ff0000';
      ctx.fillRect(x, y, width, height);

      // Draw sensor info
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 24px Arial';
      ctx.fillText(sensor.name || `Sensor ${index + 1}`, x + 10, y + 30);
      ctx.font = '20px Arial';
      ctx.fillText(`State: ${sensor.state || 'unknown'}`, x + 10, y + 60);

      if (sensor.battery !== undefined) {
        ctx.fillText(`Battery: ${sensor.battery}%`, x + 10, y + 90);
      }

      if (sensor.signal !== undefined) {
        ctx.fillText(`Signal: ${sensor.signal}`, x + 10, y + 120);
      }

      // Draw additional sensor data if available
      if (sensor.temperature !== undefined) {
        ctx.fillText(`Temp: ${sensor.temperature}°${sensor.temperatureUnit || 'F'}`, x + 10, y + 150);
      }

      if (sensor.humidity !== undefined) {
        ctx.fillText(`Humidity: ${sensor.humidity}%`, x + 10, y + 180);
      }
    });

    // Draw header
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 36px Arial';
    ctx.fillText('⚠️ ALARM SENSORS ⚠️', 20, 40);
  } else {
    // Normal dashboard display with pagination
    const sensorsPerPage = 12;
    const startIdx = currentPage * sensorsPerPage;
    const sensorsToShow = sensorData.slice(startIdx, startIdx + sensorsPerPage);

    // Draw sensors in a grid
    const columns = 4;
    const rows = 3;
    const width = config.width / columns;
    const height = config.height / rows;

    sensorsToShow.forEach((sensor, index) => {
      const x = (index % columns) * width;
      const y = Math.floor(index / columns) * height;

      // Determine background color based on sensor state
      let bgColor = '#333333';
      if (sensor.state === 'alarm' || sensor.state === 'leak' ||
          sensor.state === 'motion' || sensor.state === 'open') {
        bgColor = '#ff0000';
      } else if (sensor.battery !== undefined && sensor.battery < 20) {
        bgColor = '#ffcc00';
      }

      // Draw sensor box
      ctx.fillStyle = bgColor;
      ctx.fillRect(x + 5, y + 5, width - 10, height - 10);

      // Draw sensor info
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 20px Arial';
      ctx.fillText(sensor.name || `Sensor ${index + 1}`, x + 15, y + 30);
      ctx.font = '16px Arial';
      ctx.fillText(`State: ${sensor.state || 'unknown'}`, x + 15, y + 55);

      if (sensor.battery !== undefined) {
        ctx.fillText(`Battery: ${sensor.battery}%`, x + 15, y + 80);
      }

      if (sensor.signal !== undefined) {
        ctx.fillText(`Signal: ${sensor.signal}`, x + 15, y + 105);
      }

      // Draw additional sensor data if available
      if (sensor.temperature !== undefined) {
        ctx.fillText(`Temp: ${sensor.temperature}°${sensor.temperatureUnit || 'F'}`, x + 15, y + 130);
      }

      if (sensor.humidity !== undefined) {
        ctx.fillText(`Humidity: ${sensor.humidity}%`, x + 15, y + 155);
      }
    });

    // Draw pagination info
    ctx.fillStyle = '#ffffff';
    ctx.font = '16px Arial';
    ctx.fillText(`Page ${currentPage + 1} of ${totalPages}`, config.width - 150, config.height - 20);
  }

  // Draw timestamp
  ctx.fillStyle = '#ffffff';
  ctx.font = '14px Arial';
  const timestamp = new Date().toLocaleString();
  ctx.fillText(`Last Updated: ${timestamp}`, 10, config.height - 20);

  // Return the rendered canvas as a JPEG buffer
  return canvas.toBuffer('image/jpeg');
}

// Initialize RTSP stream
function initializeRtspStream() {
  try {
    // Create a temporary directory for the stream if it doesn't exist
    const streamDir = '/tmp/streams';
    if (!fs.existsSync(streamDir)) {
      fs.mkdirSync(streamDir, { recursive: true });
    }

    // Path for the temporary image file that will be streamed
    const imagePath = path.join(streamDir, 'dashboard.jpg');

    // Refresh rate for ffmpeg (milliseconds)
    const refreshRate = Math.floor(1000 / config.frameRate);

    // Generate first frame
    const initialFrame = renderDashboard();
    fs.writeFileSync(imagePath, initialFrame);

    // Configuration for the stream
    const streamOptions = {
      name: config.streamName,
      streamUrl: `rtsp://${config.serverIp}:${config.rtspPort}/${config.streamName}`,
      wsPort: 9999, // Internal WebSocket port for ffmpeg
      ffmpegOptions: {
        '-f': 'image2',
        '-r': config.frameRate.toString(),
        '-i': imagePath,
        '-c:v': 'libx264',
        '-preset': 'ultrafast',
        '-tune': 'zerolatency',
        '-pix_fmt': 'yuv420p',
        '-profile:v': 'baseline',
        '-b:v': '2M',
        '-bufsize': '2M',
        '-maxrate': '2M',
        '-g': (config.frameRate * 2).toString(),
        '-f': 'rtsp',
        '-rtsp_transport': 'tcp'
      }
    };

    // Start the RTSP stream
    rtspStream = new Stream(streamOptions);
    console.log(`RTSP stream started: rtsp://${config.serverIp}:${config.rtspPort}/${config.streamName}`);

    // Set up frame update interval - use a more efficient approach for very low frame rates
    const updateFrame = async () => {
      try {
        const currentTime = Date.now();

        // Only update the frame if something has changed or after a specific time interval
        // For 1 FPS, we'll update regardless, but could be optimized further
        const frame = renderDashboard();
        fs.writeFileSync(imagePath, frame);

        lastFrameTime = currentTime;

        // Schedule next update using setTimeout instead of setInterval
        // This gives more precise timing and avoids overlapping calls
        setTimeout(updateFrame, refreshRate);
      } catch (err) {
        console.error('Error updating frame:', err);
        setTimeout(updateFrame, refreshRate);
      }
    };

    // Start the frame update loop
    updateFrame();

    // Initialize ONVIF service if enabled
    if (config.enableOnvif) {
      onvifService = new OnvifService(config);
      onvifService.initialize(`rtsp://${config.serverIp}:${config.rtspPort}/${config.streamName}`);
    }

    return true;
  } catch (err) {
    console.error('Failed to initialize RTSP stream:', err);
    return false;
  }
}

// Set up page cycling
setInterval(() => {
  if (totalPages > 1 && alarmSensors.length === 0) {
    currentPage = (currentPage + 1) % totalPages;
  }
}, config.cycleInterval);

// API endpoint to check server status
app.get('/status', (req, res) => {
  const streamUrl = `rtsp://${config.serverIp}:${config.rtspPort}/${config.streamName}`;
  const onvifUrl = config.enableOnvif ? `onvif://${config.serverIp}:${config.onvifPort}` : null;

  res.json({
    status: 'online',
    sensors: {
      total: sensorData.length,
      alarmsActive: alarmSensors.length
    },
    stream: {
      rtspUrl: streamUrl,
      onvifUrl: onvifUrl,
      frameRate: config.frameRate,
      resolution: `${config.width}x${config.height}`,
      currentPage: currentPage + 1,
      totalPages
    },
    lastUpdate: new Date().toISOString()
  });
});

// API endpoint to restart the stream if needed
app.post('/restart-stream', (req, res) => {
  try {
    if (rtspStream) {
      rtspStream.stop();
      console.log('RTSP stream stopped');
    }

    setTimeout(() => {
      if (initializeRtspStream()) {
        res.json({ success: true, message: 'RTSP stream restarted successfully' });
      } else {
        res.status(500).json({ success: false, message: 'Failed to restart RTSP stream' });
      }
    }, 1000);
  } catch (err) {
    console.error('Error restarting stream:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// API endpoint to get a static image of the current view
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

// Start the server
server.listen(3001, () => {
  console.log('YoLink Dashboard RTSP Streamer started on port 3001');
  console.log(`Server IP: ${config.serverIp}`);

  // Initialize RTSP stream
  if (initializeRtspStream()) {
    console.log('RTSP stream initialized successfully');
  } else {
    console.error('Failed to initialize RTSP stream');
  }

  // Connect to dashboard for sensor data
  connectToDashboard();
});

// Handle shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  if (rtspStream) {
    rtspStream.stop();
  }
  if (onvifService) {
    onvifService.stop();
  }
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down...');
  if (rtspStream) {
    rtspStream.stop();
  }
  if (onvifService) {
    onvifService.stop();
  }
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});