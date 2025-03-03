const { spawn } = require('child_process');

class RtspStreamer {
  constructor(config, renderer) {
    this.config = config;
    this.renderer = renderer;
    this.ffmpegProcess = null;
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
      // Start FFmpeg with MJPEG input to force JPEG recognition
      this.startRTSPServer();

      // Immediately write an initial frame
      const initialFrame = this.renderer.renderFrame();
      if (this.ffmpegProcess && this.ffmpegProcess.stdin.writable) {
        // Optional: log first two bytes to confirm JPEG header (should be 0xFF, 0xD8)
        console.log('Initial frame header bytes:', initialFrame[0].toString(16), initialFrame[1].toString(16));
        this.ffmpegProcess.stdin.write(initialFrame, (err) => {
          if (err) {
            console.error('Error writing initial frame:', err);
            this.handleStreamError();
          } else {
            // Start frame updates after a brief pause to ensure FFmpeg parses the header
            setTimeout(() => this.updateFrame(), 200);
          }
        });
      } else {
        throw new Error('FFmpeg stdin is not writable during initialization.');
      }
    } catch (err) {
      console.error('Failed to initialize RTSP stream:', err);
      this.handleStreamError();
    }
  }

  startRTSPServer() {
    // Use -f mjpeg to indicate input is a stream of JPEG images
    const ffmpegArgs = [
      '-f', 'mjpeg',
      '-framerate', String(this.config.frameRate || 1),
      '-i', 'pipe:0',
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
      if (this.ffmpegProcess && this.ffmpegProcess.stdin.writable) {
        this.ffmpegProcess.stdin.write(frame, (err) => {
          if (err) {
            console.error('Error writing frame to ffmpeg stdin:', err);
            this.handleStreamError();
          }
        });
      } else {
        console.error('FFmpeg process STDIN not writable');
      }

      // Log occasionally
      if (Math.random() < 0.01) {
        console.log('Frame sent to ffmpeg successfully');
      }

      this.updateInterval = setTimeout(
        () => this.updateFrame(),
        1000 / (this.config.frameRate || 1)
      );
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
