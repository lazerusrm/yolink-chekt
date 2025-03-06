# YoLink-Chekt Integration

A complete integration between YoLink sensors and alarm/monitoring systems.

## New Feature: RTSP Streaming with ONVIF Support

This release adds RTSP streaming capabilities to the YoLink-Chekt dashboard, allowing you to:

- View your YoLink sensor dashboard in any RTSP-compatible viewer
- Add the dashboard as a camera in your NVR system using RTSP or ONVIF
- Show sensors in alarm state full-screen with a red background
- Automatically cycle through pages of sensors if they don't all fit on one screen

### Accessing the Stream

- **RTSP Stream**: `rtsp://[your-host-ip]:554/yolink-dashboard`
- **ONVIF Device**: `onvif://[your-host-ip]:80`
- **HTTP API**: `http://[your-host-ip]:80/status`
- **Snapshot**: `http://[your-host-ip]:80/onvif/snapshot`

### Key Features

- **Real-time Updates**: Sensors in alarm state are immediately shown full-screen
- **Low Resource Usage**: Uses just 1 FPS to minimize CPU and bandwidth usage
- **NVR Integration**: Compatible with most NVR systems through RTSP or ONVIF
- **Automatic Page Cycling**: If you have more sensors than fit on one screen, the view will cycle every 10 seconds

For complete details, see the [RTSP Streamer README](rtsp-streamer/README.md).

## Setup and Configuration

1. Make sure all required environmental variables are set in your `.env` file
2. The RTSP streamer service will automatically start with the rest of the system when you run:
   ```
   docker-compose up -d
   ```

## Viewing the Stream

You can access the RTSP stream in any compatible player, such as:
- VLC Media Player: `rtsp://[your-host-ip]:8554/yolink-dashboard`
- NVR Systems: Add as an IP camera using the RTSP URL or ONVIF protocol
- Smart Home Systems: Many support RTSP camera integration

## Configuration Options

Edit your `.env` file to customize the RTSP streamer:

```
# RTSP Streamer Configuration
RTSP_PORT=554
RTSP_API_PORT=80
ONVIF_PORT=80
STREAM_NAME=yolink-dashboard
FRAME_RATE=1
WIDTH=1920
HEIGHT=1080
CYCLE_INTERVAL=10000
ENABLE_ONVIF=true
```