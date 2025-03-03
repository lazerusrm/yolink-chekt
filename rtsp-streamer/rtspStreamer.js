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
  }

  initialize() {
    try {
      const streamDir = path.dirname(this.imagePath);
      if (!fs.existsSync(streamDir)) {
        fs.mkdirSync(streamDir, { recursive: true });
        console.log(`Created stream directory: ${streamDir}`);
      }

      const initialFrame = this.renderer.renderFrame();
      fs.writeFileSync(this.imagePath, initialFrame);

      const streamOptions = {
        name: this.config.streamName,
        streamUrl: `rtsp://${this.config.serverIp}:${this.config.rtspPort}/${this.config.streamName}`,
        wsPort: 9999,
        ffmpegOptions: {
          '-loop': '1',
          '-f': 'image2',
          '-r': this.config.frameRate.toString(),
          '-i': this.imagePath,
          '-c:v': 'libx264',
          '-preset': 'ultrafast',
          '-tune': 'zerolatency',
          '-pix_fmt': 'yuv420p',
          '-profile:v': 'baseline',
          '-b:v': '2M',
          '-bufsize': '2M',
          '-maxrate': '2M',
          '-g': (this.config.frameRate * 2).toString(),
          '-f': 'rtsp',
          '-rtsp_transport': 'tcp',
        },
      };

      this.stream = new Stream(streamOptions);
      console.log(`RTSP stream started at ${streamOptions.streamUrl}`);

      this.updateFrame();
    } catch (err) {
      console.error('Failed to initialize RTSP stream:', err);
      this.restartStream();
    }
  }

  updateFrame() {
    try {
      const frame = this.renderer.renderFrame();
      fs.writeFileSync(this.imagePath, frame);
      this.updateInterval = setTimeout(() => this.updateFrame(), 1000 / this.config.frameRate);
    } catch (err) {
      console.error('Error updating frame:', err);
      this.restartStream();
    }
  }

  restartStream() {
    if (this.stream) {
      this.stream.stop();
      console.log('RTSP stream stopped');
    }
    if (this.updateInterval) {
      clearTimeout(this.updateInterval);
    }
    setTimeout(() => this.initialize(), 2000);
  }

  stop() {
    if (this.stream) {
      this.stream.stop();
      console.log('RTSP stream stopped manually');
    }
    if (this.updateInterval) {
      clearTimeout(this.updateInterval);
    }
  }
}

module.exports = RtspStreamer;*