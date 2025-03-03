const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

class RtspStreamer {
  constructor(config, renderer) {
    this.config = config;
    this.renderer = renderer;
    this.tempDir = '/tmp/streams';
    this.frameFile = path.join(this.tempDir, 'current_frame.jpg');
    this.inputListPath = path.join(this.tempDir, 'input.txt');
    this.ffmpegProcess = null;
    this.updateInterval = null;
    this.isStopping = false;
    this.retryCount = 0;
    this.maxRetries = 5;
    this.frameCount = 0;

    // For RTSP server
    this.rtspPort = this.config.rtspPort || 8554;
    this.rtspUrl = `rtsp://${this.config.serverIp}:${this.rtspPort}/${this.config.streamName}`;

    // Flag to track initialization state
    this.isInitialized = false;
  }

  initialize() {
    if (this.isStopping || this.isInitialized) return;

    try {
      this.setupTempDir()
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

  async setupTempDir() {
    // Ensure the directory for temporary files exists
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true });
      console.log(`Created directory for temporary files: ${this.tempDir}`);
    }

    // Write an initial frame file
    const initialFrame = this.renderer.renderFrame();
    fs.writeFileSync(this.frameFile, initialFrame);
    console.log(`Created initial frame file at ${this.frameFile}`);

    return true;
  }

  async startFFmpegProcess() {
    return new Promise((resolve, reject) => {
      // Using a completely different approach with image2 demuxer
      // This uses a single input file that we'll update between frames
      const ffmpegArgs = [
        // Input options
        '-re',                                       // Read input at native framerate
        '-loop', '1',                                // Loop the input (we'll replace the file)
        '-framerate', String(this.config.frameRate || 1), // Input framerate
        '-i', this.frameFile,                        // Input file that we'll update

        // Video encoding options - using more compatible settings
        '-c:v', 'libx264',                           // H.264 encoder
        '-preset', 'ultrafast',                      // Fastest encoding preset for low latency
        '-tune', 'zerolatency',                      // Tune for low latency
        '-profile:v', 'baseline',                    // Most compatible profile
        '-level', '4.0',                             // Compatible level for 1080p
        '-pix_fmt', 'yuv420p',                       // Required pixel format for H.264
        '-vf', 'format=yuv420p',                     // Force yuv420p pixel format
        '-r', String(this.config.frameRate || 1),    // Output framerate
        '-g', '30',                                  // Keyframe interval
        '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2', // Ensure dimensions are even

        // RTSP output options
        '-f', 'rtsp',                                // Output format RTSP
        '-rtsp_transport', 'tcp',                    // Use TCP for RTSP (more reliable)
        this.rtspUrl                                 // Output URL
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

        // Only log key messages to keep logs cleaner
        if (message.includes('Error') || message.includes('error') || message.includes('Invalid') ||
            message.includes('warning') || message.includes('Could not')) {
          console.error('FFmpeg stderr:', message);
        }

        // Look for indicators of successful initialization
        if (message.includes('fps=') || message.includes('frame=')) {
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

      // Write the frame to the file that FFmpeg is reading
      // Use a unique temporary filename to avoid partial reads
      const tempFileName = `${this.tempDir}/frame_tmp_${Date.now()}.jpg`;

      // Write to temp file first
      fs.writeFileSync(tempFileName, frame);

      // Then rename to the file FFmpeg is reading (atomic operation)
      fs.renameSync(tempFileName, this.frameFile);

      this.frameCount++;

      // Log frame count occasionally for monitoring
      if (this.frameCount % 10 === 0) {
        console.log(`Updated frame file ${this.frameCount} times`);
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

    // Kill the FFmpeg process
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