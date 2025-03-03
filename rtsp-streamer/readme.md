# YoLink Dashboard RTSP Streamer

This component adds RTSP streaming capabilities to the YoLink-Chekt dashboard, allowing you to view your sensor dashboard in any RTSP-compatible viewer or NVR system. It also includes ONVIF protocol support for better integration with camera systems and NVRs.

## Features

- Creates an RTSP stream of the YoLink dashboard
- Provides ONVIF compatibility for discovery and device management
- Displays sensors in alarm state full-screen with a red background
- Cycles through pages of sensors every 10 seconds if all can't fit on one screen
- Provides HTTP API endpoints for status and management
- Generates snapshots on demand

## Stream URLs

The dashboard will be available at:

- **RTSP Stream**: `rtsp://[your-host-ip]:8554/yolink-dashboard`
- **ONVIF Device**: `onvif://[your-host-ip]:8555`

## Configuration

The following environment variables can be configured in the docker-compose.yml file:

| Variable | Description | Default |
|----------|-------------|---------|
| DASHBOARD_URL | URL to the YoLink dashboard | http://dashboard:3000 |
| RTSP_PORT | Port for the RTSP stream | 8554 |
| STREAM_NAME | Name of the RTSP stream | yolink-dashboard |
| FRAME_RATE | Frames per second for the stream | 1 |
| WIDTH | Width of the stream | 1920 |
| HEIGHT | Height of the stream | 1080 |
| CYCLE_INTERVAL | Time (ms) between page cycles | 10000 |
| ONVIF_PORT | Port for ONVIF services | 8555 |
| ENABLE_ONVIF | Enable/disable ONVIF compatibility | true |
| SERVER_IP | Override the auto-detected server IP | (auto-detected) |

## API Endpoints

### Status Check
```
GET http://[your-host-ip]:3001/status
```

Returns JSON with information about the streamer status, number of sensors, active alarms, and stream URLs.

### Get Snapshot
```
GET http://[your-host-ip]:3001/snapshot
```

Returns a JPEG image of the current dashboard view.

### Restart Stream
```
POST http://[your-host-ip]:3001/restart-stream
```

Restarts the RTSP stream if it's having issues.

## Integration with NVR Systems

### RTSP Stream

Most NVR systems that support RTSP can add this as a camera source:

1. In your NVR, add a new IP camera
2. Select "RTSP" or "Custom" as the protocol
3. Enter the RTSP URL: `rtsp://[your-host-ip]:8554/yolink-dashboard`
4. Use the following settings:
   - No authentication
   - Transport protocol: TCP (preferred) or UDP
   - Stream type: Main stream

### ONVIF Integration

For NVRs or monitoring systems that support ONVIF:

1. In your NVR, use the auto-discovery feature to find ONVIF devices
2. The YoLink Dashboard should appear as "YoLink Dashboard-RTSP"
3. Or manually add using: `onvif://[your-host-ip]:8555`

## Troubleshooting

### Stream Not Connecting

Check that:
1. The container is running (`docker ps`)
2. The ports are correctly mapped (8554, 8555, 3001)
3. The dashboard is accessible from the RTSP streamer container
4. Your firewall allows traffic on the required ports

For detailed logs run:
```
docker logs yolink-rtsp-streamer
```

### Stream Performance Issues

If you experience performance issues:
1. Try reducing the resolution via WIDTH/HEIGHT environment variables
2. Lower the FRAME_RATE
3. Ensure your host has sufficient CPU resources

### ONVIF Discovery Problems

If your NVR can't discover the device via ONVIF:
1. Make sure UDP port 1900 is open for WS-Discovery
2. Try adding the device manually using the ONVIF URL
3. Check if your NVR supports ONVIF Profile S

## Notes on Resource Usage

The RTSP streaming is optimized for sensor monitoring with a very low frame rate (1 FPS) by default, which significantly reduces CPU usage and bandwidth requirements. The low frame rate is perfect for sensor monitoring since:

1. Motion sensors only update on motion
2. Door contacts only update on state change
3. Temperature sensors typically update every 15+ minutes
4. The stream automatically updates immediately when sensors go into alarm state

If you're running on extremely limited hardware and need to further reduce resource usage:
1. Consider using a lower resolution (e.g., 1280x720)
2. If you don't need ONVIF support, disable it by setting `ENABLE_ONVIF=false`