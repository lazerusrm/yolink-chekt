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

    // For RTSP server
    this.rtspPort = this.config.rtspPort || 8554;
    this.rtspUrl = `rtsp://${this.config.serverIp}:${this.rtspPort}/${this.config.streamName}`;
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

      // Start simple RTSP server (using ffserver approach)
      this.startRTSPServer();

      // Start updating frames
      this.updateFrame();
    } catch (err) {
      console.error('Failed to initialize RTSP stream:', err);
      this.handleStreamError();
    }
  }

  startRTSPServer() {
    // First, start ffmpeg to generate an RTSP stream using TCP
    const ffmpegArgs = [
      '-re',
      '-loop', '1',
      '-framerate', String(this.config.frameRate || 1),
      '-i', this.imagePath,
      '-c:v', 'libx264',
      '-profile:v', 'baseline',
      '-pix_fmt', 'yuv420p',
      '-f', 'rtsp',
      '-rtsp_transport', 'tcp',
      '-muxdelay', '0.1',
      this.rtspUrl
    ];

    console.log('Starting FFmpeg RTSP server with command:', 'ffmpeg', ffmpegArgs.join(' '));

    this.ffmpegProcess = spawn('ffmpeg', ffmpegArgs, {
      detached: false,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    this.ffmpegProcess.stdout.on('data', (data) => {
      console.log('FFmpeg stdout:', data.toString());
    });

    this.ffmpegProcess.stderr.on('data', (data) => {
      const message = data.toString();
      // Filter out repetitive messages
      if (message.includes('Error') || message.includes('error') || message.includes('warning')) {
        console.error('FFmpeg stderr:', message);
      }
    });

    this.ffmpegProcess.on('close', (code) => {
      console.log(`FFmpeg process exited with code ${code}`);
      if (!this.isStopping && code !== 0) {
        this.handleStreamError();
      }
    });

    console.log(`RTSP stream should be available at: ${this.rtspUrl}`);
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
      console.error(`Max retries (${this.maxRetries}) reached. Please check configuration and restart manually.`);
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