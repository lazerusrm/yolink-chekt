const express = require('express');

function createApiRouter(renderer, streamer, config) {
  const router = express.Router();

  router.get('/status', (req, res) => {
    try {
      const streamUrl = `rtsp://${config.serverIp}:${config.rtspPort}/${config.streamName}`;
      const onvifUrl = config.enableOnvif ? `onvif://${config.serverIp}:${config.onvifPort}` : null;
      res.json({
        status: 'online',
        sensors: {
          total: renderer.sensorData.length,
          alarmsActive: renderer.alarmSensors.length,
        },
        stream: {
          rtspUrl: streamUrl,
          onvifUrl,
          frameRate: config.frameRate,
          resolution: `${config.width}x${config.height}`,
          currentPage: renderer.currentPage + 1,
          totalPages: renderer.totalPages,
        },
        lastUpdate: new Date().toISOString(),
      });
    } catch (err) {
      console.error('Error in /status endpoint:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

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

  router.post('/restart-stream', (req, res) => {
    try {
      streamer.restartStream();
      res.json({ success: true, message: 'Stream restart initiated' });
    } catch (err) {
      console.error('Error restarting stream:', err);
      res.status(500).json({ success: false, message: 'Failed to restart stream' });
    }
  });

  return router;
}

module.exports = createApiRouter;