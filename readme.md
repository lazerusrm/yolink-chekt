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
ONVIF_PORT=8000
STREAM_NAME=yolink-dashboard
FRAME_RATE=1
WIDTH=1920
HEIGHT=1080
CYCLE_INTERVAL=10000
ENABLE_ONVIF=true
```

# YoLink Integration System - Asynchronous Architecture

## System Overview

The YoLink Integration System connects YoLink IoT devices to various receiver systems (CHEKT alarm panels, SIA receivers, and Modbus relays) using asynchronous processing patterns. This document explains the technical architecture after the async refactoring.

## Core Components

### 1. Redis Connection Manager

The Redis Connection Manager provides a centralized connection pool for all Redis operations, improving efficiency and reliability.

**Key Features**:
- Single connection pool shared across modules
- Exponential backoff reconnection strategy
- Graceful resource cleanup
- Connection status monitoring

**Implementation**: `redis_manager.py`

### 2. Configuration Management

The Configuration module handles loading, caching, and saving system settings with full async support.

**Key Features**:
- Asynchronous loading and saving
- Configuration caching with TTL
- Default configuration handling
- Validation of inputs

**Implementation**: `config.py`

### 3. Device Management

The Device Management module handles device data and state tracking with proper async patterns.

**Key Features**:
- State tracking for all devices
- Asynchronous API communication
- Data normalization
- Efficient bulk operations

**Implementation**: `device_manager.py`

### 4. MQTT Clients

Two independent MQTT clients handle communication with YoLink and external monitoring systems.

**YoLink MQTT Client**:
- Receives device state updates
- Handles authentication token refresh
- Reconnects with exponential backoff
- Processes messages asynchronously

**Monitor MQTT Client**:
- Publishes device status updates
- Maintains persistent connection
- Reports connection status
- Ensures message delivery

**Implementations**: `yolink_mqtt.py`, `monitor_mqtt.py`

### 5. Modbus Relay Control

The Modbus Relay module provides control over physical relays via ModbusTCP.

**Key Features**:
- Support for pymodbus 3.8.6
- Pulse and follower modes
- Channel testing capabilities
- Coil-based relay control

**Implementation**: `modbus_relay.py`

### 6. Alert Processing

The Alert module processes device events and routes them to appropriate receivers.

**Key Features**:
- Multi-receiver support (CHEKT, SIA, Modbus)
- Door prop alarm handling
- State change detection
- Event mapping

**Implementation**: `alerts.py`

### 7. Web Interface

The web interface provides configuration, monitoring, and control capabilities.

**Key Features**:
- Real-time status monitoring
- Device configuration
- Mapping management
- System testing

**Implementation**: `app.py`, `index.html`, `config.html`

## Data Flow

The system's data flow follows this general pattern:

1. **Device State Changes**:
   - YoLink devices publish state changes to YoLink cloud
   - YoLink cloud forwards to MQTT broker
   - System receives updates via MQTT

2. **Data Processing**:
   - `yolink_mqtt.py` receives MQTT messages
   - Messages are parsed and normalized
   - Device state is updated in Redis
   - State changes trigger alert evaluation

3. **Alert Processing**:
   - `alerts.py` evaluates if state change should trigger an alert
   - Alert is routed to appropriate receiver(s)
   - Confirmation and status are tracked

4. **Monitoring**:
   - Device status is published to monitoring MQTT
   - Web interface displays current status
   - System metrics are tracked

## Asynchronous Patterns

The system uses these async patterns throughout:

### 1. Task Management

```python
# Task creation
task = asyncio.create_task(some_async_function())

# Task tracking for cleanup
app.bg_tasks.append(task)

# Task cancellation during shutdown
for task in app.bg_tasks:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
```

### 2. Concurrent Operations

```python
# Concurrent API calls
results = await asyncio.gather(
    fetch_home_info(),
    fetch_device_list(),
    return_exceptions=True
)

# Process results with error handling
for result in results:
    if isinstance(result, Exception):
        handle_error(result)
    else:
        process_result(result)
```

### 3. Resource Management

```python
# Resource acquisition and cleanup
async with aiohttp.ClientSession() as session:
    async with session.post(url, json=data) as response:
        result = await response.json()
        # Resources automatically cleaned up
```

### 4. Reconnection Strategy

```python
# Exponential backoff with jitter
retry_count = 0
while not shutdown_event.is_set():
    try:
        # Attempt connection
        await connect()
        retry_count = 0  # Reset on success
    except ConnectionError:
        retry_count += 1
        delay = min(MAX_DELAY, BASE_DELAY * (2 ** retry_count))
        jitter = 0.1 * delay * random()
        await asyncio.sleep(delay + jitter)
```

## Error Handling

The system implements comprehensive error handling:

1. **Contextual Error Handling**:
   - Each operation handles its specific errors
   - Log appropriate context for debugging
   - Return meaningful status codes

2. **Retries with Backoff**:
   - Network operations use retry with backoff
   - Prevent overwhelming external services
   - Graceful degradation on failure

3. **Circuit Breakers**:
   - Detection of persistent failures
   - Temporary suspension of failing operations
   - Periodic retry to restore service

4. **User Feedback**:
   - Clear error messages in UI
   - Toast notifications for transient errors
   - Status indicators for persistent issues

## Connection Management

Connections are managed following these principles:

1. **Lazy Initialization**:
   - Connections are established on first use
   - Resources aren't wasted on unused connections

2. **Connection Pooling**:
   - Redis uses a shared connection pool
   - HTTP requests use sessions with keep-alive

3. **Connection Monitoring**:
   - Active health checks for critical connections
   - Automatic reconnection for failed connections
   - Status reporting for operational visibility

4. **Graceful Shutdown**:
   - Proper cleanup of all connections
   - Waiting for in-progress operations
   - Cancellation of pending operations

## Web Interface Architecture

The web interface follows these patterns:

1. **Asynchronous Routes**:
   - All endpoints are async
   - Long-running operations don't block the server
   - Background tasks for periodic operations

2. **Client-Side Enhancements**:
   - AJAX with retry for resilience
   - Optimistic UI updates for responsiveness
   - Toast notifications for feedback
   - Streaming updates for real-time monitoring

3. **Form Handling**:
   - Client and server validation
   - Appropriate error feedback
   - Prevention of duplicate submissions

## Security Considerations

1. **Authentication**:
   - User authentication with password hashing
   - TOTP-based two-factor authentication
   - Session management

2. **Authorization**:
   - Route protection with decorators
   - Limited access to critical functions

3. **Data Protection**:
   - Sensitive configuration data encryption
   - Password handling best practices
   - Token management for third-party services

## Performance Optimization

1. **Caching Strategy**:
   - Configuration caching with TTL
   - Device data caching
   - UI state caching

2. **Minimal Network Operations**:
   - Batched updates where possible
   - Debounced UI actions
   - Prioritized critical operations

3. **Efficient Processing**:
   - Parallel processing with asyncio.gather
   - Non-blocking I/O throughout
   - Resource pooling

## Monitoring and Diagnostics

1. **Logging**:
   - Structured logging with context
   - Log rotation and retention
   - Log level configuration

2. **Status Reporting**:
   - Connection status indicators
   - Last operation timestamps
   - Error tracking and reporting

3. **Metrics**:
   - Device communication status
   - System uptime monitoring
   - Connection performance tracking

## Conclusion

The asynchronous architecture of the YoLink Integration System provides a resilient, efficient platform for connecting IoT devices to various receiver systems. The use of modern async patterns ensures scalability, responsiveness, and reliability while minimizing resource consumption.