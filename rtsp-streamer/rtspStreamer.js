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
    this.retryCount = 0;
    this.maxRetries = 5;
  }

  initialize() {
    if (this.isStopping) return;

    try {
      // Create the stream directory if it doesn't exist
      const streamDir = path.dirname(this.imagePath);
      if (!fs.existsSync(streamDir)) {
        fs.mkdirSync(streamDir, { recursive: true });
        console.log(`Created stream directory: ${streamDir}`);
      }

      // Write an initial frame to ensure the file exists
      const initialFrame = this.renderer.renderFrame();
      fs.writeFileSync(this.imagePath, initialFrame);
      console.log('Initial frame written to', this.imagePath);

      // Set up stream options with simplified FFmpeg options
      const streamOptions = {
        name: this.config.streamName || 'yolink-dashboard',
        streamUrl: `rtsp://${this.config.serverIp}:${this.config.rtspPort}/${this.config.streamName}`,
        wsPort: this.config.wsPort || 9999,
        ffmpegOptions: {
          // Simplified FFmpeg options
          '-f': 'image2',
          '-re': '',
          '-loop': '1',
          '-r': String(this.config.frameRate || 1),
          '-i': this.imagePath,
          '-c:v': 'libx264',
          '-tune': 'zerolatency',
          '-preset': 'ultrafast',
          '-pix_fmt': 'yuv420p',
          '-f': 'rtsp',
          '-rtsp_transport': 'tcp'
        }
      };

      // Log the command that will be executed
      console.log("FFmpeg command options:", JSON.stringify(streamOptions.ffmpegOptions));

      // Create the stream
      try {
        console.log(`Creating RTSP stream at ${streamOptions.streamUrl} with WebSocket port ${streamOptions.wsPort}`);
        this.stream = new Stream(streamOptions);
        console.log(`RTSP stream initialized successfully`);
        this.retryCount = 0;

        // Start updating frames
        this.updateFrame();
      } catch (streamError) {
        console.error('Error creating RTSP stream:', streamError);
        this.handleStreamError();
      }
    } catch (err) {
      console.error('Failed to initialize RTSP stream:', err);
      this.handleStreamError();
    }
  }

  updateFrame() {
    if (this.isStopping) return;

    try {
      const frame = this.renderer.renderFrame();
      fs.writeFileSync(this.imagePath, frame);

      // Log frame updates occasionally
      if (Math.random() < 0.01) {
        console.log('Frame updated successfully');
      }

      this.updateInterval = setTimeout(() => this.updateFrame(), 1000 / (this.config.frameRate || 1));
    } catch (err) {
      console.error('Error updating frame:', err);
      this.handleStreamError();
    }
  }

  handleStreamError() {
    if (this.isStopping) return;

    this.retryCount++;
    if (this.retryCount <= this.maxRetries) {
      const delay = Math.min(10000, 1000 * Math.pow(2, this.retryCount - 1));
      console.log(`Retry ${this.retryCount}/${this.maxRetries} in ${delay}ms...`);
      this.stop();
      setTimeout(() => this.initialize(), delay);
    } else {
      console.error(`Max retries (${this.maxRetries}) reached. Please check configuration.`);
      this.stop();
    }
  }

  restartStream() {
    console.log('Restarting RTSP stream...');
    this.retryCount = 0;
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