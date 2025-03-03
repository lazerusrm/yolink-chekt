const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

class RtspStreamer {
  constructor(config, renderer) {
    this.config = config;
    this.renderer = renderer;
    this.pipeDir = '/tmp/streams';
    this.pipePath = path.join(this.pipeDir, 'dashboard_pipe');
    this.ffmpegProcess = null;
    this.pipeWriteStream = null;
    this.updateInterval = null;
    this.isStopping = false;
    this.retryCount = 0;
    this.maxRetries = 5;
    this.frameCount = 0;

    // For RTSP server
    this.rtspPort = this.config.rtspPort || 8554;
    this.rtspUrl = `rtsp://${this.config.serverIp}:${this.rtspPort}/${this.config.streamName}`;

    // Add a flag to track initialization state
    this.isInitialized = false;
  }

  initialize() {
    if (this.isStopping || this.isInitialized) return;

    try {
      this.setupPipe()
        .then(() => this.startFFmpegProcess())
        .then(() => this.startFrameUpdates())
        .catch(err => {
          console.error('Error during initialization:', err);
          this.handleStreamError();
        });
    } catch (err) {
      console.error('Exception during initialization:', err);
      this.handleStreamError();
    }
  }

  async setupPipe() {
    // Ensure the directory for the pipe exists
    if (!fs.existsSync(this.pipeDir)) {
      fs.mkdirSync(this.pipeDir, { recursive: true });
      console.log(`Created directory for pipe: ${this.pipeDir}`);
    }

    // Remove any existing pipe to avoid stale FIFOs
    if (fs.existsSync(this.pipePath)) {
      try {
        fs.unlinkSync(this.pipePath);
        console.log(`Removed existing pipe: ${this.pipePath}`);
      } catch (err) {
        console.warn(`Could not remove existing pipe: ${err.message}`);
      }
    }

    // Create a new named pipe (FIFO)
    console.log(`Creating FIFO at ${this.pipePath}`);
    try {
      execSync(`mkfifo ${this.pipePath}`);
    } catch (err) {
      throw new Error(`Failed to create FIFO: ${err.message}`);
    }

    return true;
  }

  async startFFmpegProcess() {
    return new Promise((resolve, reject) => {
      // More resilient FFmpeg configuration
      const ffmpegArgs = [
        '-f', 'mjpeg',                              // Input format is MJPEG
        '-framerate', String(this.config.frameRate || 1), // Input framerate
        '-use_wallclock_as_timestamps', '1',        // Use system clock for timestamps
        '-i', this.pipePath,                        // Input from FIFO
        '-c:v', 'libx264',                          // H.264 encoder
        '-preset', 'ultrafast',                     // Fastest encoding preset for low latency
        '-tune', 'zerolatency',                     // Tune for low latency
        '-profile:v', 'baseline',                   // Most compatible profile
        '-level', '3.0',                            // Compatibility level
        '-pix_fmt', 'yuv420p',                      // Required pixel format for H.264
        '-r', String(this.config.frameRate || 1),   // Output framerate
        '-g', '30',                                 // Keyframe interval
        '-bufsize', '1000k',                        // Encoder buffer size
        '-f', 'rtsp',                               // Output format RTSP
        '-rtsp_transport', 'tcp',                   // Use TCP for RTSP (more reliable)
        '-muxdelay', '0.1',                         // Low muxing delay
        this.rtspUrl                                // Output URL
      ];

      console.log('Starting FFmpeg RTSP server with command:', 'ffmpeg', ffmpegArgs.join(' '));

      this.ffmpegProcess = spawn('ffmpeg', ffmpegArgs, {
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let startupOutput = '';
      let errorOutput = '';
      let initialized = false;

      this.ffmpegProcess.stdout.on('data', (data) => {
        const message = data.toString();
        startupOutput += message;
        console.log('FFmpeg stdout:', message);
      });

      this.ffmpegProcess.stderr.on('data', (data) => {
        const message = data.toString();
        errorOutput += message;

        // Only log errors and warnings to keep logs cleaner
        if (message.includes('Error') || message.includes('error') || message.includes('Invalid') ||
            message.includes('warning') || message.includes('Could not')) {
          console.error('FFmpeg stderr:', message);
        } else if (message.includes('fps=') || message.includes('frame=')) {
          // This indicates FFmpeg is successfully processing frames
          if (!initialized) {
            initialized = true;
            resolve();
          }
        }
      });

      this.ffmpegProcess.on('close', (code) => {
        console.log(`FFmpeg process exited with code ${code}`);
        if (!this.isStopping) {
          if (code !== 0) {
            // Provide more context when failing
            console.error('FFmpeg process failed with error output:', errorOutput);
            reject(new Error(`FFmpeg exited with code ${code}`));
          } else if (!initialized) {
            reject(new Error('FFmpeg process terminated before initialization completed'));
          }
          this.handleStreamError();
        }
      });

      // Set a timeout to resolve or reject if FFmpeg doesn't respond in time
      setTimeout(() => {
        if (!initialized) {
          if (errorOutput.includes('Invalid data') || errorOutput.includes('Error')) {
            reject(new Error(`FFmpeg initialization failed: ${errorOutput}`));
          } else {
            console.log('FFmpeg not initialized but continuing (this is normal for the first run)');
            resolve();
          }
        }
      }, 5000);

      console.log(`RTSP stream should be available at: ${this.rtspUrl}`);
    });
  }

  async startFrameUpdates() {
    // Open a write stream to the FIFO
    this.pipeWriteStream = fs.createWriteStream(this.pipePath);

    this.pipeWriteStream.on('error', (err) => {
      console.error('Pipe write stream error:', err);
      this.handleStreamError();
    });

    // Mark as initialized now that everything is ready
    this.isInitialized = true;

    // Start sending frames
    this.updateFrame();
    return true;
  }

  updateFrame() {
    if (this.isStopping || !this.isInitialized) return;

    try {
      // Render a new frame
      const frame = this.renderer.renderFrame();

      // Check if pipe is writable before attempting to write
      if (this.pipeWriteStream && this.pipeWriteStream.writable) {
        this.pipeWriteStream.write(frame, (err) => {
          if (err) {
            console.error('Error writing frame to FIFO:', err);
            // Only handle as error if not a broken pipe (which is common when stopping)
            if (err.code !== 'EPIPE' || !this.isStopping) {
              this.handleStreamError();
            }
          } else {
            this.frameCount++;
            // Log frame count occasionally for monitoring
            if (this.frameCount % 10 === 0) {
              console.log(`Sent ${this.frameCount} frames to RTSP stream`);
            }
          }
        });
      } else {
        if (!this.isStopping) {
          console.error('FIFO write stream is not writable');
        }
      }

      // Schedule next frame based on frame rate
      const frameDelay = 1000 / (this.config.frameRate || 1);
      this.updateInterval = setTimeout(() => this.updateFrame(), frameDelay);
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

      // Stop everything cleanly before restarting
      this.stop();

      // Reset initialization flag
      this.isInitialized = false;

      // Attempt to restart after delay
      setTimeout(() => this.initialize(), delay);
    } else {
      console.error(`Max retries (${this.maxRetries}) reached. Please check configuration and restart manually.`);
      this.stop();
    }
  }

  restartStream() {
    console.log('Manually restarting RTSP stream...');
    this.retryCount = 0;
    this.frameCount = 0;
    this.stop();

    // Reset initialization flag
    this.isInitialized = false;

    setTimeout(() => this.initialize(), 2000);
    return true;
  }

  stop() {
    if (this.isStopping) return;

    this.isStopping = true;
    console.log('Stopping RTSP stream components...');

    // Clear the frame update interval first
    if (this.updateInterval) {
      clearTimeout(this.updateInterval);
      this.updateInterval = null;
      console.log('Frame update interval cleared');
    }

    // Close the pipe write stream
    if (this.pipeWriteStream) {
      try {
        this.pipeWriteStream.end();
        console.log('Pipe write stream closed');
      } catch (err) {
        console.error('Error closing pipe write stream:', err);
      }
      this.pipeWriteStream = null;
    }

    // Kill the FFmpeg process last
    if (this.ffmpegProcess) {
      try {
        this.ffmpegProcess.kill('SIGTERM');
        console.log('FFmpeg process terminated');
      } catch (err) {
        console.error('Error stopping FFmpeg process:', err);
        // Force kill if normal termination fails
        try {
          this.ffmpegProcess.kill('SIGKILL');
        } catch (innerErr) {
          console.error('Failed to force kill FFmpeg process:', innerErr);
        }
      }
      this.ffmpegProcess = null;
    }

    this.isStopping = false;
    console.log('RTSP stream stopped');
  }
}

module.exports = RtspStreamer;