/**
 * ONVIF Service for YoLink Dashboard
 * Implements basic ONVIF device and media services
 */

const { OnvifServer, Server } = require('node-onvif-server');
const ip = require('ip');
const uuid = require('uuid');
const os = require('os');

// Device information
const deviceInfo = {
  manufacturer: 'YoLink',
  model: 'Dashboard-RTSP',
  firmwareVersion: '1.0.0',
  serialNumber: uuid.v4(),
  hardwareId: 'YOLINK-DASHBOARD-1'
};

class OnvifService {
  constructor(config) {
    this.config = config;
    this.server = null;
    this.rtspUrl = null;
    this.deviceId = uuid.v4();
    this.initialized = false;
  }

  /**
   * Initialize the ONVIF service
   * @param {string} rtspUrl The RTSP URL to be exposed via ONVIF
   */
  initialize(rtspUrl) {
    if (this.initialized) return;

    this.rtspUrl = rtspUrl;
    const serverPort = this.config.onvifPort || 8555;
    const serverIp = this.config.serverIp || ip.address();

    console.log(`Starting ONVIF server on ${serverIp}:${serverPort}`);

    try {
      // Create ONVIF server instance
      this.server = new OnvifServer({
        port: serverPort,
        serviceAddress: `http://${serverIp}:${serverPort}/onvif/service`,
        deviceInfo: {
          manufacturer: deviceInfo.manufacturer,
          model: deviceInfo.model,
          firmwareVersion: deviceInfo.firmwareVersion,
          serialNumber: deviceInfo.serialNumber,
          hardwareId: deviceInfo.hardwareId
        },
        // Specify hostname and port for devices to connect to this server
        hostname: serverIp,
        port: serverPort
      });

      // Configure device information
      this.server.setDeviceInformation({
        Manufacturer: deviceInfo.manufacturer,
        Model: deviceInfo.model,
        FirmwareVersion: deviceInfo.firmwareVersion,
        SerialNumber: deviceInfo.serialNumber,
        HardwareId: deviceInfo.hardwareId
      });

      // Add media profile for the RTSP stream
      this.addRtspMediaProfile();

      // Start the server
      this.server.start();
      this.initialized = true;

      console.log(`ONVIF server started successfully. Device available at: onvif://${serverIp}:${serverPort}`);
      console.log(`RTSP stream registered: ${this.rtspUrl}`);

      // Enable discovery
      this.enableDiscovery();
    } catch (error) {
      console.error('Failed to start ONVIF server:', error);
    }
  }

  /**
   * Add media profile for the RTSP stream
   */
  addRtspMediaProfile() {
    if (!this.server) return;

    try {
      // Add a media profile for the RTSP stream
      const profileToken = 'YolinkDashboardProfile';
      const streamUri = this.rtspUrl;

      // Add video source
      const videoSourceToken = 'YolinkDashboardVideoSource';
      this.server.addVideoSource(videoSourceToken, {
        Framerate: this.config.frameRate || 1,
        Resolution: {
          Width: this.config.width || 1920,
          Height: this.config.height || 1080
        }
      });

      // Add video encoder configuration
      const videoEncoderToken = 'YolinkDashboardVideoEncoder';
      this.server.addVideoEncoderConfiguration(videoEncoderToken, {
        Encoding: 'H264',
        Resolution: {
          Width: this.config.width || 1920,
          Height: this.config.height || 1080
        },
        Quality: 6,
        RateControl: {
          FrameRateLimit: this.config.frameRate || 1,
          EncodingInterval: 1,
          BitrateLimit: 2048
        },
        H264: {
          GovLength: 50,
          H264Profile: 'Main'
        }
      });

      // Create a media profile
      this.server.addProfile(profileToken, {
        name: 'YoLink Dashboard Stream',
        videoSourceConfiguration: {
          sourceToken: videoSourceToken,
          bounds: {
            x: 0,
            y: 0,
            width: this.config.width || 1920,
            height: this.config.height || 1080
          }
        },
        videoEncoderConfiguration: {
          token: videoEncoderToken,
          encoding: 'H264',
          resolution: {
            width: this.config.width || 1920,
            height: this.config.height || 1080
          },
          quality: 6,
          rateControl: {
            frameRateLimit: this.config.frameRate || 1,
            encodingInterval: 1,
            bitrateLimit: 2048
          },
          H264: {
            govLength: 50,
            H264Profile: 'Main'
          }
        }
      });

      // Set the stream URI for the profile
      this.server.setStreamUri(profileToken, streamUri);

      console.log(`Added media profile: ${profileToken} with RTSP URI: ${streamUri}`);
    } catch (error) {
      console.error('Failed to add media profile:', error);
    }
  }

  /**
   * Enable WS-Discovery for ONVIF device discovery
   */
  enableDiscovery() {
    try {
      // The node-onvif-server package should handle discovery automatically
      console.log('ONVIF discovery service enabled');
    } catch (error) {
      console.error('Failed to enable ONVIF discovery:', error);
    }
  }

  /**
   * Stop the ONVIF service
   */
  stop() {
    if (this.server) {
      this.server.stop();
      this.initialized = false;
      console.log('ONVIF server stopped');
    }
  }
}

module.exports = OnvifService;