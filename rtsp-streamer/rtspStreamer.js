/**
 * RTSP Streamer for YoLink Dashboard
 * Handles creating and managing the RTSP stream
 */

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

      // Set up stream options
      const streamOptions = {
        name: this.config.streamName || 'yolink-dashboard',
        streamUrl: `rtsp://${this.config.serverIp}:${this.config.rtspPort}/${this.config.streamName}`,
        wsPort: this.config.wsPort || 9999, // Only specify wsPort for WebSocket
        ffmpegOptions: {
          '-re': '',                                     // Real-time input
          '-f': 'image2',                                // Input format is image
          '-loop': '1',                                  // Loop the image
          '-framerate': String(this.config.frameRate || 1),  // Frame rate
          '-i': this.imagePath,                          // Input file path
          '-c:v': 'libx264',                             // Video codec
          '-preset': 'ultrafast',                        // Encoding preset
          '-tune': 'zerolatency',                        // Tune for low latency
          '-pix_fmt': 'yuv420p',                         // Pixel format
          '-b:v': '2M',                                  // Video bitrate
          '-bufsize': '2M',                              // Buffer size
          '-maxrate': '2M',                              // Maximum bitrate
          '-g': String((this.config.frameRate || 1) * 2), // GOP size
          '-f': 'rtsp',                                  // Output format
          '-rtsp_transport': 'tcp'                       // RTSP transport protocol
        }
      };

      // Create the stream with error handlers
      try {
        this.stream = new Stream(streamOptions);
        console.log(`RTSP stream initialized at ${streamOptions.streamUrl}`);
        this.retryCount = 0; // Reset retry count on success

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
      // Use a less verbose log for frame updates to avoid log flooding
      if (Math.random() < 0.05) { // Only log occasionally (about 5% of frames)
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
      const delay = Math.min(10000, 1000 * Math.pow(2, this.retryCount - 1)); // Exponential backoff
      console.log(`Retry ${this.retryCount}/${this.maxRetries} in ${delay}ms...`);
      this.stop();
      setTimeout(() => this.initialize(), delay);
    } else {
      console.error(`Max retries (${this.maxRetries}) reached. Please check configuration and restart manually.`);
      this.stop();
    }
  }

  restartStream() {
    console.log('Restarting RTSP stream...');
    this.retryCount = 0; // Reset retry count for manual restart
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