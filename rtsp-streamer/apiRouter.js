/**
 * API Router for YoLink RTSP Streamer
 * Provides HTTP endpoints for status, snapshots, and stream management
 */

const express = require('express');

function createApiRouter(renderer, streamer, config) {
  const router = express.Router();

  // Status endpoint - returns current state of the system
  router.get('/status', (req, res) => {
    try {
      const streamUrl = `rtsp://${config.serverIp}:${config.rtspPort}/${config.streamName}`;
      const onvifUrl = config.enableOnvif ? `onvif://${config.serverIp}:${config.onvifPort}` : null;

      res.json({
        status: 'online',
        sensors: {
          total: renderer.sensorData.length,
          alarmsActive: renderer.alarmSensors.length,
          activeSensors: renderer.sensorData.filter(s => s.last_seen && s.last_seen.includes('2025')).length
        },
        stream: {
          rtspUrl: streamUrl,
          onvifUrl,
          frameRate: config.frameRate,
          resolution: `${config.width}x${config.height}`,
          currentPage: renderer.currentPage + 1,
          totalPages: renderer.totalPages,
        },
        system: {
          uptime: process.uptime(),
          memory: process.memoryUsage()
        },
        lastUpdate: new Date().toISOString(),
      });
    } catch (err) {
      console.error('Error in /status endpoint:', err);
      res.status(500).json({
        error: 'Internal server error',
        message: err.message
      });
    }
  });

  // Snapshot endpoint - returns the current frame as JPEG
  router.get('/snapshot', (req, res) => {
    try {
      const frame = renderer.renderFrame();
      res.contentType('image/jpeg');
      res.send(frame);
    } catch (err) {
      console.error('Error generating snapshot:', err);
      res.status(500).send('Failed to generate snapshot');
    }
  });

  // Stream restart endpoint
  router.post('/restart-stream', (req, res) => {
    try {
      streamer.restartStream();
      res.json({
        success: true,
        message: 'Stream restart initiated',
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('Error restarting stream:', err);
      res.status(500).json({
        success: false,
        message: 'Failed to restart stream',
        error: err.message
      });
    }
  });

  // Sensor list endpoint
  router.get('/sensors', (req, res) => {
    try {
      // Extract only the necessary fields to reduce response size
      const sensors = renderer.sensorData.map(s => ({
        name: s.name,
        type: s.type,
        state: s.state,
        battery: s.battery,
        signal: s.signal,
        last_seen: s.last_seen,
        temperature: s.temperature,
        humidity: s.humidity
      }));

      res.json({
        count: sensors.length,
        sensors: sensors
      });
    } catch (err) {
      console.error('Error in /sensors endpoint:', err);
      res.status(500).json({ error: 'Failed to retrieve sensor data' });
    }
  });

  // Page control endpoints
  router.post('/page/:pageNum', (req, res) => {
    try {
      const pageNum = parseInt(req.params.pageNum, 10);
      if (isNaN(pageNum) || pageNum < 1 || pageNum > renderer.totalPages) {
        return res.status(400).json({
          error: 'Invalid page number',
          valid_range: `1-${renderer.totalPages}`
        });
      }

      renderer.setPage(pageNum - 1); // Convert from 1-based to 0-based
      res.json({
        success: true,
        current_page: pageNum,
        total_pages: renderer.totalPages
      });
    } catch (err) {
      console.error('Error setting page:', err);
      res.status(500).json({ error: 'Failed to set page' });
    }
  });

  return router;
}

module.exports = createApiRouter;