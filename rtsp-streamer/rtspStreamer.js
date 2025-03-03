cat > /tmp/rtspStreamer.js << 'EOF'
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

class RtspStreamer {
  constructor(config, renderer) {
    this.config = config;
    this.renderer = renderer;
    this.imagePath = path.join('/tmp/streams', 'dashboard.jpg');
    this.updateInterval = null;
    this.ffmpegProcess = null;
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

      // Start ffmpeg directly
      this.startFFmpeg();

      // Start updating frames
      this.updateFrame();
    } catch (err) {
      console.error('Failed to initialize RTSP stream:', err);
      this.handleStreamError();
    }
  }

  startFFmpeg() {
    const rtspUrl = `rtsp://${this.config.serverIp}:${this.config.rtspPort}/${this.config.streamName}`;

    // Build ffmpeg command
    const ffmpegArgs = [
      '-re',                // Read input at native frame rate
      '-f', 'image2',       // Force image format
      '-loop', '1',         // Loop the input
      '-r', this.config.frameRate.toString(), // Frame rate
      '-i', this.imagePath, // Input file
      '-c:v', 'libx264',    // Video codec
      '-preset', 'ultrafast',
      '-tune', 'zerolatency',
      '-pix_fmt', 'yuv420p',
      '-f', 'rtsp',         // Output format
      '-rtsp_transport', 'tcp',
      rtspUrl               // Output URL
    ];

    console.log('Starting FFmpeg with command: ffmpeg', ffmpegArgs.join(' '));

    // Start FFmpeg process
    this.ffmpegProcess = spawn('ffmpeg', ffmpegArgs);

    // Handle FFmpeg output
    this.ffmpegProcess.stdout.on('data', (data) => {
      console.log(`FFmpeg stdout: ${data}`);
    });

    this.ffmpegProcess.stderr.on('data', (data) => {
      // FFmpeg logs to stderr by default, so only log important messages
      const message = data.toString();
      if (message.includes('Error') || message.includes('error') || message.includes('warning')) {
        console.error(`FFmpeg stderr: ${message}`);
      }
    });

    this.ffmpegProcess.on('close', (code) => {
      console.log(`FFmpeg process exited with code ${code}`);
      if (!this.isStopping && code !== 0) {
        this.handleStreamError();
      }
    });

    console.log(`RTSP stream started at ${rtspUrl}`);
  }

  updateFrame() {
    if (this.isStopping) return;

    try {
      const frame = this.renderer.renderFrame();
      fs.writeFileSync(this.imagePath, frame);

      // Only log occasionally to avoid filling logs
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

    if (this.ffmpegProcess) {
      try {
        this.ffmpegProcess.kill('SIGTERM');
        console.log('FFmpeg process terminated');
      } catch (err) {
        console.error('Error stopping FFmpeg process:', err);
      }
      this.ffmpegProcess = null;
    }

    if (this.updateInterval) {
      clearTimeout(this.updateInterval);
      this.updateInterval = null;
    }

    this.isStopping = false;
  }
}

module.exports = RtspStreamer;
EOF

docker cp /tmp/rtspStreamer.js yolink-rtsp-streamer:/app/
docker restart yolink-rtsp-streamer