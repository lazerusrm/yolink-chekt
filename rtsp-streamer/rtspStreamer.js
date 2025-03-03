const Stream = require('node-rtsp-stream');
const fs = require('fs');
const path = require('path');

class RtspStreamer {
  constructor(config, renderer) {
    this.config = config;
    this.renderer = renderer;
    this.stream = null;
    this.imagePath = path.join('/tmp/streams', 'dashboard.jpg');
    this.updateInterval = null;
    this.isStopping = false;
  }

  initialize() {
    if (this.isStopping) return;

    try {
      const streamDir = path.dirname(this.imagePath);
      if (!fs.existsSync(streamDir)) {
        fs.mkdirSync(streamDir, { recursive: true });
        console.log(`Created stream directory: ${streamDir}`);
      }

      // Write an initial frame to ensure the file exists
      const initialFrame = this.renderer.renderFrame();
      fs.writeFileSync(this.imagePath, initialFrame);
      console.log('Initial frame written to', this.imagePath);

      const streamOptions = {
        name: this.config.streamName || 'yolink-dashboard',
        streamUrl: `rtsp://${this.config.serverIp}:${this.config.rtspPort}/${this.config.streamName}`,
        port: this.config.wsPort || 9999, // WebSocket port for RTSP clients
        ffmpegOptions: {
          '-re': '', // Real-time input
          '-loop': '1',
          '-f': 'image2',
          '-r': String(this.config.frameRate || 1),
          '-i': this.imagePath,
          '-c:v': 'libx264',
          '-preset': 'ultrafast',
          '-tune': 'zerolatency',
          '-pix_fmt': 'yuv420p',
          '-b:v': '2M',
          '-bufsize': '2M',
          '-maxrate': '2M',
          '-g': String((this.config.frameRate || 1) * 2),
          '-f': 'rtsp',
          '-rtsp_transport': 'tcp'
        }
      };

      this.stream = new Stream(streamOptions);
      console.log(`RTSP stream initialized at ${streamOptions.streamUrl}`);

      this.stream.on('error', (err) => {
        console.error('RTSP stream error:', err);
        this.restartStream();
      });

      this.stream.on('exit', (code) => {
        console.log(`RTSP stream exited with code ${code}`);
        if (!this.isStopping) this.restartStream();
      });

      this.updateFrame();
    } catch (err) {
      console.error('Failed to initialize RTSP stream:', err);
      this.restartStream();
    }
  }

  updateFrame() {
    if (this.isStopping) return;

    try {
      const frame = this.renderer.renderFrame();
      fs.writeFileSync(this.imagePath, frame);
      console.log('Frame updated successfully');
      this.updateInterval = setTimeout(() => this.updateFrame(), 1000 / (this.config.frameRate || 1));
    } catch (err) {
      console.error('Error updating frame:', err);
      this.restartStream();
    }
  }

  restartStream() {
    if (this.isStopping) return;

    console.log('Attempting to restart RTSP stream...');
    this.stop();
    setTimeout(() => this.initialize(), 2000);
  }

  stop() {
    this.isStopping = true;
    if (this.stream) {
      try {
        this.stream.stop();
        console.log('RTSP stream stopped');
      } catch (err) {
        console.error('Error stopping RTSP stream:', err);
      }
      this.stream = null;
    }
    if (this.updateInterval) {
      clearTimeout(this.updateInterval);
      this.updateInterval = null;
    }
    this.isStopping = false;
  }
}

module.exports = RtspStreamer;