const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

class RtspStreamer {
  constructor(config, renderer) {
    this.config = config;
    this.renderer = renderer;
    this.pipePath = path.join('/tmp/streams', 'dashboard_pipe');
    this.ffmpegProcess = null;
    this.pipeWriteStream = null;
    this.updateInterval = null;
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
      // Ensure the directory for the pipe exists
      const pipeDir = path.dirname(this.pipePath);
      if (!fs.existsSync(pipeDir)) {
        fs.mkdirSync(pipeDir, { recursive: true });
        console.log(`Created directory for pipe: ${pipeDir}`);
      }

      // Create a named pipe (FIFO) if it doesn't exist
      if (!fs.existsSync(this.pipePath)) {
        console.log(`Creating FIFO at ${this.pipePath}`);
        execSync(`mkfifo ${this.pipePath}`);
      }

      // Start FFmpeg reading from the FIFO
      this.startRTSPServer();

      // Open a persistent write stream to the FIFO
      this.pipeWriteStream = fs.createWriteStream(this.pipePath);
      this.pipeWriteStream.on('error', (err) => {
        console.error('Pipe write stream error:', err);
        this.handleStreamError();
      });

      // Immediately write an initial frame so FFmpeg can negotiate headers
      const initialFrame = this.renderer.renderFrame();
      this.pipeWriteStream.write(initialFrame, (err) => {
        if (err) {
          console.error('Error writing initial frame:', err);
          this.handleStreamError();
        } else {
          // Give FFmpeg a moment to parse the header, then start frame updates
          setTimeout(() => this.updateFrame(), 200);
        }
      });
    } catch (err) {
      console.error('Failed to initialize RTSP stream:', err);
      this.handleStreamError();
    }
  }

  startRTSPServer() {
    // Use -f mjpeg to tell FFmpeg that the input stream is a series of JPEG images
    const ffmpegArgs = [
      '-f', 'mjpeg',
      '-framerate', String(this.config.frameRate || 1),
      '-i', this.pipePath,
      '-c:v', 'libx264',
      '-profile:v', 'baseline',
      '-pix_fmt', 'yuv420p',
      '-f', 'rtsp',
      '-rtsp_transport', 'tcp',
      '-muxdelay', '0.1',
      this.rtspUrl
    ];

    console.log('Starting FFmpeg RTSP server with command:', 'ffmpeg', ffmpegArgs.join(' '));

    this.ffmpegProcess = spawn('ffmpeg', ffmpegArgs, { stdio: ['ignore', 'pipe', 'pipe'] });

    this.ffmpegProcess.stdout.on('data', (data) => {
      console.log('FFmpeg stdout:', data.toString());
    });

    this.ffmpegProcess.stderr.on('data', (data) => {
      const message = data.toString();
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
      if (this.pipeWriteStream && this.pipeWriteStream.writable) {
        this.pipeWriteStream.write(frame, (err) => {
          if (err) {
            console.error('Error writing frame to FIFO:', err);
            this.handleStreamError();
          }
        });
      } else {
        console.error('FIFO write stream is not writable');
      }

      // Schedule next frame based on frame rate
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

    if (this.pipeWriteStream) {
      this.pipeWriteStream.end();
      this.pipeWriteStream = null;
    }

    if (this.updateInterval) {
      clearTimeout(this.updateInterval);
      this.updateInterval = null;
    }

    this.isStopping = false;
  }
}

module.exports = RtspStreamer;
