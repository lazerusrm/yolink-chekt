# YoLink Dashboard RTSP Server with ONVIF Support

A Python service that renders YoLink sensor data as an RTSP video stream and exposes it as an ONVIF-compatible camera device. This allows the dashboard to be viewed in NVR systems, security monitors, and other platforms that support ONVIF cameras.

## Features

- **RTSP Streaming**: Creates a real-time video stream of YoLink sensor dashboard
- **ONVIF Protocol Support**: Implements ONVIF Profile S for compatibility with NVR systems
- **Multi-Profile Streaming**: Provides streams at different resolutions:
  - Main Profile (1920x1080 @ 6fps, 20 sensors per page)
  - Low-Resolution Profile (960x540 @ 4fps, 6 sensors per page)
  - Mobile Profile (480x270 @ 2fps, 4 sensors per page)
- **Dynamic Layout**: Automatically adjusts sensors-per-page based on resolution
- **Snapshot Support**: Provides real-time image snapshots via ONVIF
- **Authentication**: Supports both Basic Auth and WS-Security
- **WS-Discovery**: Properly announces itself on the network for auto-discovery
- **Bye Messages**: Correctly announces device removal when service stops
- **API Endpoints**: Provides REST API for control and monitoring

## Requirements

- Python 3.9+
- FFmpeg (for RTSP streaming)
- Dependencies:
  - Flask
  - Pillow
  - websocket-client
  - Werkzeug

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/yolink-dashboard.git
   cd yolink-dashboard
   ```

2. Install the package:
   ```bash
   pip install -e .
   ```

3. Ensure FFmpeg is installed:
   ```bash
   # Debian/Ubuntu
   sudo apt install ffmpeg

   # macOS
   brew install ffmpeg

   # Windows
   # Download from https://ffmpeg.org/download.html and add to PATH
   ```

## Configuration

The application is configured through environment variables:

### Core Settings
- `SERVER_IP`: IP address to bind to (defaults to auto-detected IP)
- `RTSP_PORT`: RTSP stream port (default: 554)
- `RTSP_API_PORT`: HTTP API port (default: 80)
- `STREAM_NAME`: Name of the RTSP stream (default: "yolink-dashboard")

### Video Quality Settings
- `WIDTH`: Video width (default: 1920)
- `HEIGHT`: Video height (default: 1080)
- `FRAME_RATE`: Frames per second (default: 6)
- `BITRATE`: Stream bitrate in kbps (default: 4000)
- `QUALITY`: Encoder quality setting (1-10, default: 5)
- `GOP`: Group of Pictures length (default: 30)
- `H264_PROFILE`: H.264 profile (Baseline, Main, High - default: High)

### ONVIF Settings
- `ENABLE_ONVIF`: Enable ONVIF service (default: true)
- `ONVIF_PORT`: ONVIF service port (default: 8000)
- `ONVIF_USERNAME`: Authentication username (default: "admin")
- `ONVIF_PASSWORD`: Authentication password (default: "123456")
- `ONVIF_AUTH_REQUIRED`: Require authentication (default: true)
- `ONVIF_AUTH_METHOD`: Auth method ("basic", "ws-security", "both", "none" - default: "both")

### Multi-Profile Settings
- `ENABLE_LOW_RES_PROFILE`: Enable low-resolution profile (default: false)
- `LOW_RES_WIDTH`: Low-res width (default: WIDTH/2)
- `LOW_RES_HEIGHT`: Low-res height (default: HEIGHT/2)
- `LOW_RES_FPS`: Low-res frame rate (default: 4)
- `LOW_RES_BITRATE`: Low-res bitrate (default: BITRATE/4)
- `LOW_RES_SENSORS_PER_PAGE`: Sensors per page for low-res (default: 6)

- `ENABLE_MOBILE_PROFILE`: Enable mobile profile (default: false)
- `MOBILE_WIDTH`: Mobile width (default: WIDTH/4)
- `MOBILE_HEIGHT`: Mobile height (default: HEIGHT/4)
- `MOBILE_FPS`: Mobile frame rate (default: 2)
- `MOBILE_BITRATE`: Mobile bitrate (default: BITRATE/10)
- `MOBILE_SENSORS_PER_PAGE`: Sensors per page for mobile (default: 4)

### Dashboard Settings
- `DASHBOARD_URL`: YoLink dashboard WebSocket URL (default: "http://websocket-proxy:3000")
- `CYCLE_INTERVAL`: Page cycling interval in ms (default: 10000)
- `SENSORS_PER_PAGE`: Sensors shown per page (default: 20)

### Device Information
- `MANUFACTURER`: Device manufacturer name (default: "YoLink")
- `MODEL`: Device model name (default: "Dashboard-RTSP")
- `FIRMWARE_VERSION`: Firmware version (default: "1.0.0")
- `HARDWARE_ID`: Hardware identifier (default: "YOLINK-DASHBOARD-1")

## Usage

### Running the Service

```bash
# Start with default settings
yolink-dashboard

# Or with custom settings
export SERVER_IP=192.168.1.100
export FRAME_RATE=6
export ENABLE_LOW_RES_PROFILE=true
export SENSORS_PER_PAGE=6
yolink-dashboard
```

### Accessing Streams

The RTSP streams are available at:
```
# Main stream
rtsp://<SERVER_IP>:<RTSP_PORT>/<STREAM_NAME>

# Low-resolution stream (if enabled)
rtsp://<SERVER_IP>:<RTSP_PORT>/<STREAM_NAME>_sub

# Mobile stream (if enabled)
rtsp://<SERVER_IP>:<RTSP_PORT>/<STREAM_NAME>_mobile
```

Example:
```
rtsp://192.168.1.100:8554/yolink-dashboard
```

### API Endpoints

- `GET /status`: Service status and stream information
- `GET /onvif/snapshot`: Current dashboard image
- `GET /sensors`: List of all sensors and their states
- `POST /page/<number>`: Set current page number (1-based)
- `POST /restart-stream`: Restart RTSP stream

### ONVIF Integration

The device will appear in ONVIF discovery tools and NVR systems. Default authentication credentials are `admin/123456`. The device advertises RTSP streaming and snapshot capabilities.

## Architecture

The service consists of several components:

- **DashboardRenderer**: Renders sensor data into visual dashboard frames
- **RtspStreamer/MultiProfileRtspStreamer**: Converts rendered frames into RTSP streams
- **WebSocketClient**: Receives real-time sensor updates
- **OnvifService**: Implements ONVIF device discovery and protocols
- **Flask Routes**: Provides REST API and SOAP endpoints

## Troubleshooting

### RTSP Stream Issues
- Ensure FFmpeg is installed and in the system PATH
- Verify no other service is using the RTSP port
- Check firewall settings for UDP/TCP ports 8554 (or custom RTSP port)

### ONVIF Discovery Issues
- Ensure client and server are on the same subnet
- Check firewall settings for UDP port 3702 (WS-Discovery)
- Verify ONVIF service is enabled with `ENABLE_ONVIF=true`

### Authentication Problems
- For testing, set `ONVIF_AUTH_REQUIRED=false`
- For clients that only support Basic Auth, set `ONVIF_AUTH_METHOD=basic`
- Default credentials are `admin/123456`

## Known Issues & Limitations

- PTZ functionality is not implemented (not relevant for dashboard views)
- For low-power devices, consider disabling low-res and mobile profiles
- High frame rates may impact performance on slower systems

## License

This project is licensed under the MIT License - see the LICENSE file for details.