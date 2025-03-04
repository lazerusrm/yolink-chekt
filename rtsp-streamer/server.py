#!/usr/bin/env python3
import os
import sys
import time
import json
import uuid
import signal
import socket
import threading
import datetime
import subprocess
import io
import logging

from flask import Flask, request, jsonify, Response
from PIL import Image, ImageDraw, ImageFont

# ----------------------
# Logging Configuration
# ----------------------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# ----------------------
# Configuration
# ----------------------
config = {
    "dashboard_url": os.environ.get("DASHBOARD_URL", "http://websocket-proxy:3000"),
    "rtsp_port": int(os.environ.get("RTSP_PORT", 8554)),
    "stream_name": os.environ.get("STREAM_NAME", "yolink-dashboard"),
    "frame_rate": int(os.environ.get("FRAME_RATE", 6)),  # Target 6 FPS
    "width": int(os.environ.get("WIDTH", 1920)),
    "height": int(os.environ.get("HEIGHT", 1080)),
    "cycle_interval": int(os.environ.get("CYCLE_INTERVAL", 10000)),  # in ms
    "http_port": int(os.environ.get("RTSP_API_PORT", 3001)),
    "ws_port": int(os.environ.get("WS_PORT", 9999)),
    "enable_onvif": os.environ.get("ENABLE_ONVIF", "true").lower() != "false",
    "onvif_port": int(os.environ.get("ONVIF_PORT", 8555)),
    "server_ip": os.environ.get("SERVER_IP", socket.gethostbyname(socket.gethostname()))
}


# ----------------------
# Helper Functions
# ----------------------
def safe_float(val):
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def get_text_width(draw, text, font):
    """Return the width of text using draw.textbbox."""
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0]


# ----------------------
# Dashboard Renderer
# ----------------------
class DashboardRenderer:
    def __init__(self, config):
        self.alarm_display_timer = 0  # When alarm view started
        self.alarm_display_duration = 30  # 30 seconds
        self.normal_display_duration = 30  # 30 seconds
        self.new_alarm_triggered = False  # Flag for new alarms
        self.config = config
        self.sensor_data = []
        self.alarm_sensors = []
        self.current_page = 0
        self.total_pages = 1
        self.last_update_time = time.time()  # Track last update for forcing refreshes
        try:
            # Use DejaVu Sans, which is commonly available in Debian-based images
            self.font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
            self.font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 18)
        except OSError as e:
            logging.warning(f"Could not load DejaVu fonts, using default fonts: {e}")
            self.font_large = ImageFont.load_default()
            self.font_small = ImageFont.load_default()
        self.previous_states = {}  # To track previous states for contact sensors

    def update_sensors(self, sensors):
        """Update sensor data and determine which sensors are in alarm state, triggering a frame refresh."""
        if not isinstance(sensors, list):
            logging.error("Invalid sensor data: not a list")
            return

        self.sensor_data = sensors
        self.alarm_sensors = []
        self.last_update_time = time.time()  # Update timestamp for frame refresh
        logging.info(f"Received {len(sensors)} sensors via WebSocket")  # Log sensor count

        for s in sensors:
            if not s:
                continue

            sensor_type = s.get("type")
            state = s.get("state")
            signal = s.get("signal")
            battery = s.get("battery")
            logging.debug(f"Processing sensor: {s.get('name', 'Unknown')} (Type: {sensor_type}, State: {state})")

            # Map battery value to percentage if it's an integer
            if battery is not None and isinstance(battery, int):
                battery = map_battery_value(battery)

            # Motion Sensors
            if sensor_type == "MotionSensor":
                if (state == "motion" or
                        (signal is not None and signal < -119) or
                        (battery is not None and battery <= 25)):  # Use 25% as low battery threshold
                    self.alarm_sensors.append(s)
                    logging.debug(
                        f"MotionSensor {s.get('name')} added to alarms: State={state}, Battery={battery}, Signal={signal}")

            # Contact Sensors (trigger alarm on "open" state or low signal/battery)
            elif sensor_type == "ContactSensor":
                previous_state = self.previous_states.get(s.get("deviceId"), "closed")
                if (state == "open" or  # Immediate alarm for open state
                        (previous_state == "closed" and state == "open") or  # State change from closed to open
                        (signal is not None and signal < -119) or
                        (battery is not None and battery <= 25)):  # Low battery threshold
                    self.alarm_sensors.append(s)
                    logging.debug(
                        f"ContactSensor {s.get('name')} added to alarms: State={state}, Previous={previous_state}, Battery={battery}, Signal={signal}")
                self.previous_states[s.get("deviceId")] = state

            # Temperature/Humidity Sensors
            elif sensor_type == "THSensor":
                alarms = s.get("alarms", {}).get("state", {})
                if any(alarms.values()) or (battery is not None and battery <= 25) or (
                        signal is not None and signal < -119):
                    self.alarm_sensors.append(s)
                    logging.debug(
                        f"THSensor {s.get('name', 'Unknown')}: Alarms={alarms}, Battery={battery}, Signal={signal}")

            # Outlets and Multi-Outlets (no alarms, just display)
            elif sensor_type in ["Outlet", "MultiOutlet"]:
                logging.debug(f"Rendering Outlet/MultiOutlet: {s}")  # Debug multi-outlet data

        # Pagination logic
        sensors_per_page = 12
        self.total_pages = max(1, (len(self.sensor_data) + sensors_per_page - 1) // sensors_per_page)
        if self.current_page >= self.total_pages:
            self.current_page = 0
        logging.info(
            f"Updated sensors: {len(self.sensor_data)}, alarms: {len(self.alarm_sensors)}, pages: {self.total_pages}")

        # Check for new alarms and reset timer if applicable
        if self.alarm_sensors and not self.new_alarm_triggered:
            self.new_alarm_triggered = True
            self.alarm_display_timer = time.time()  # Start or restart timer for alarm view

    def render_frame(self, width, height):
        current_time = time.time()
        image = Image.new("RGB", (width, height), "#000000")
        draw = ImageDraw.Draw(image)

        # Always render latest data, cycling between alarm and normal views
        if self.alarm_sensors and (current_time - self.alarm_display_timer < self.alarm_display_duration):
            self.render_alarm_view(draw)  # Show alarm view for 30 seconds
            logging.debug("Rendering alarm view")
        elif current_time - self.alarm_display_timer < self.alarm_display_duration + self.normal_display_duration:
            self.render_normal_view(draw)  # Show normal view for 30 seconds
            logging.debug("Rendering normal view")
        else:
            self.alarm_display_timer = 0  # Reset timer
            self.new_alarm_triggered = False  # Reset flag
            self.render_normal_view(draw)  # Default to normal view
            logging.debug("Rendering default normal view")

        return image

    def render_normal_view(self, draw):
        """Render the normal view with relevant fields for each sensor type."""
        draw.rectangle([(0, 0), (draw.im.size[0], 50)], fill="#333333")
        draw.text((10, 10), "SENSORS", font=self.font_large, fill="#ffffff")

        sensors_per_page = 12
        start_idx = self.current_page * sensors_per_page
        end_idx = min(start_idx + sensors_per_page, len(self.sensor_data))
        sensors_to_show = self.sensor_data[start_idx:end_idx]

        for i, sensor in enumerate(sensors_to_show):
            x = 10 + (i % 4) * 200
            y = 60 + (i // 4) * 150
            draw.rectangle([(x, y), (x + 190, y + 140)], outline="#ffffff")
            draw.text((x + 10, y + 10), sensor.get("name", "Unknown"), font=self.font_small, fill="#ffffff")

            sensor_type = sensor.get("type")
            state = sensor.get("state", "N/A")
            if sensor_type == "THSensor" and isinstance(state, dict):
                state_text = format_smoke_state(state)
            else:
                state_text = state
            draw.text((x + 10, y + 30), f"State: {state_text}", font=self.font_small, fill="#ffffff")
            y_offset = 50

            if sensor_type in ["MotionSensor", "ContactSensor"]:
                if "battery" in sensor and sensor["battery"] is not None:
                    battery_value = map_battery_value(sensor["battery"])
                    if battery_value is not None:
                        battery_text = f"Battery: {battery_value}%"
                        draw.text((x + 10, y + y_offset), battery_text, font=self.font_small, fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    draw.text((x + 10, y + y_offset), f"Signal: {sensor['signal']}", font=self.font_small,
                              fill="#ffffff")
                    y_offset += 20

            elif sensor_type == "THSensor":
                logging.debug(f"Rendering THSensor: {sensor}")  # Add debugging
                if sensor.get("temperature", "unknown") != "unknown":
                    draw.text((x + 10, y + y_offset),
                              f"Temp: {sensor['temperature']}°{sensor.get('temperatureUnit', 'F')}",
                              font=self.font_small, fill="#ffffff")
                    y_offset += 20
                if sensor.get("humidity", "unknown") != "unknown":
                    draw.text((x + 10, y + y_offset), f"Humidity: {sensor['humidity']}%", font=self.font_small,
                              fill="#ffffff")
                    y_offset += 20
                if "battery" in sensor and sensor["battery"] is not None:
                    battery_value = map_battery_value(sensor["battery"])
                    if battery_value is not None:
                        battery_text = f"Battery: {battery_value}%"
                        draw.text((x + 10, y + y_offset), battery_text, font=self.font_small, fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    draw.text((x + 10, y + y_offset), f"Signal: {sensor['signal']}", font=self.font_small,
                              fill="#ffffff")
                    y_offset += 20

            elif sensor_type in ["Outlet", "MultiOutlet"]:
                if "power" in sensor or "powers" in sensor:  # Handle single or multiple power values
                    powers = sensor.get("power", sensor.get("powers", []))
                    if isinstance(powers, (int, float)):
                        draw.text((x + 10, y + y_offset), f"Power: {powers}W", font=self.font_small, fill="#ffffff")
                    elif isinstance(powers, list):
                        for i, power in enumerate(powers[:2]):  # Limit to 2 for space
                            draw.text((x + 10, y + y_offset + (i * 20)), f"Outlet {i + 1} Power: {power}W",
                                      font=self.font_small, fill="#ffffff")
                    y_offset += len(powers) * 20 if isinstance(powers, list) else 20
                if "watt" in sensor or "watts" in sensor:  # Handle single or multiple watt values
                    watts = sensor.get("watt", sensor.get("watts", []))
                    if isinstance(watts, (int, float)):
                        draw.text((x + 10, y + y_offset), f"Watt: {watts}W", font=self.font_small, fill="#ffffff")
                    elif isinstance(watts, list):
                        for i, watt in enumerate(watts[:2]):  # Limit to 2 for space
                            draw.text((x + 10, y + y_offset + (i * 20)), f"Outlet {i + 1} Watt: {watt}W",
                                      font=self.font_small, fill="#ffffff")
                    y_offset += len(watts) * 20 if isinstance(watts, list) else 20
                if "signal" in sensor:
                    draw.text((x + 10, y + y_offset), f"Signal: {sensor['signal']}", font=self.font_small,
                              fill="#ffffff")
                    y_offset += 20
                logging.debug(f"Rendering Outlet/MultiOutlet: {sensor}")  # Add debugging

    def render_alarm_view(self, draw):
        """Render the alarm view with relevant fields for alarmed sensors."""
        draw.rectangle([(0, 0), (draw.im.size[0], 50)], fill="#ff0000")
        draw.text((10, 10), "ALARM SENSORS", font=self.font_large, fill="#ffffff")

        for i, sensor in enumerate(self.alarm_sensors[:12]):  # Limit to 12 for display
            x = 10 + (i % 4) * 200
            y = 60 + (i // 4) * 150
            draw.rectangle([(x, y), (x + 190, y + 140)], outline="#ffffff")
            draw.text((x + 10, y + 10), sensor.get("name", "Unknown"), font=self.font_small, fill="#ffffff")

            sensor_type = sensor.get("type")
            state = sensor.get("state", "N/A")
            if sensor_type == "THSensor" and isinstance(state, dict):
                state_text = format_smoke_state(state)
            else:
                state_text = state
            draw.text((x + 10, y + 30), f"State: {state_text}", font=self.font_small, fill="#ffffff")
            y_offset = 50

            if sensor_type in ["MotionSensor", "ContactSensor"]:
                if "battery" in sensor and sensor["battery"] is not None:
                    battery_value = map_battery_value(sensor["battery"])
                    if battery_value is not None:
                        battery_text = f"Battery: {battery_value}%"
                        draw.text((x + 10, y + y_offset), battery_text, font=self.font_small, fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    draw.text((x + 10, y + y_offset), f"Signal: {sensor['signal']}", font=self.font_small,
                              fill="#ffffff")
                    y_offset += 20

            elif sensor_type == "THSensor":
                if sensor.get("temperature", "unknown") != "unknown":
                    draw.text((x + 10, y + y_offset),
                              f"Temp: {sensor['temperature']}°{sensor.get('temperatureUnit', 'F')}",
                              font=self.font_small, fill="#ffffff")
                    y_offset += 20
                if sensor.get("humidity", "unknown") != "unknown":
                    draw.text((x + 10, y + y_offset), f"Humidity: {sensor['humidity']}%", font=self.font_small,
                              fill="#ffffff")
                    y_offset += 20
                if "battery" in sensor and sensor["battery"] is not None:
                    battery_value = map_battery_value(sensor["battery"])
                    if battery_value is not None:
                        battery_text = f"Battery: {battery_value}%"
                        draw.text((x + 10, y + y_offset), battery_text, font=self.font_small, fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    draw.text((x + 10, y + y_offset), f"Signal: {sensor['signal']}", font=self.font_small,
                              fill="#ffffff")
                    y_offset += 20

            elif sensor_type in ["Outlet", "MultiOutlet"]:
                if "power" in sensor or "powers" in sensor:  # Handle single or multiple power values
                    powers = sensor.get("power", sensor.get("powers", []))
                    if isinstance(powers, (int, float)):
                        draw.text((x + 10, y + y_offset), f"Power: {powers}W", font=self.font_small, fill="#ffffff")
                    elif isinstance(powers, list):
                        for i, power in enumerate(powers[:2]):  # Limit to 2 for space
                            draw.text((x + 10, y + y_offset + (i * 20)), f"Outlet {i + 1} Power: {power}W",
                                      font=self.font_small, fill="#ffffff")
                    y_offset += len(powers) * 20 if isinstance(powers, list) else 20
                if "watt" in sensor or "watts" in sensor:  # Handle single or multiple watt values
                    watts = sensor.get("watt", sensor.get("watts", []))
                    if isinstance(watts, (int, float)):
                        draw.text((x + 10, y + y_offset), f"Watt: {watts}W", font=self.font_small, fill="#ffffff")
                    elif isinstance(watts, list):
                        for i, watt in enumerate(watts[:2]):  # Limit to 2 for space
                            draw.text((x + 10, y + y_offset + (i * 20)), f"Outlet {i + 1} Watt: {watt}W",
                                      font=self.font_small, fill="#ffffff")
                    y_offset += len(watts) * 20 if isinstance(watts, list) else 20
                if "signal" in sensor:
                    draw.text((x + 10, y + y_offset), f"Signal: {sensor['signal']}", font=self.font_small,
                              fill="#ffffff")
                    y_offset += 20
                logging.debug(f"Rendering Outlet/MultiOutlet: {sensor}")  # Add debugging


# ----------------------
# WebSocket Client
# ----------------------
import websocket


class WebSocketClient(threading.Thread):
    def __init__(self, url, renderer):
        super().__init__()
        self.url = url
        self.renderer = renderer
        self.ws = None
        self.daemon = True

    def run(self):
        while True:
            try:
                self.ws = websocket.create_connection(self.url)
                logging.info(f"Connected to WebSocket: {self.url}")
                while True:
                    try:
                        msg = self.ws.recv()
                        logging.debug(f"Received WebSocket message: {msg}")  # Log raw message for debugging
                        try:
                            data = json.loads(msg)
                            if data.get("type") == "sensors-update":
                                sensors = data.get("sensors", [])
                                logging.info(f"Received {len(sensors)} sensors via WebSocket")
                                self.renderer.update_sensors(sensors)
                        except json.JSONDecodeError as e:
                            logging.error(f"Invalid JSON in WebSocket message: {e}. Raw message: {msg}")
                            continue  # Skip this message and wait for the next one
                    except Exception as e:
                        logging.error(f"Error processing WebSocket message: {e}")
                        continue  # Skip the error and continue listening
            except Exception as e:
                logging.error(f"WebSocket error: {e}")
                time.sleep(2)  # Wait before reconnecting

    def close(self):
        if self.ws:
            self.ws.close()


# ----------------------
# RTSP Streamer (Updated for 6 FPS with stability fixes)
# ----------------------
class RtspStreamer(threading.Thread):
    def __init__(self, config, renderer):
        super().__init__()
        self.config = config
        self.renderer = renderer
        self.ffmpeg_process = None
        self.daemon = True
        self.pipe_path = "/tmp/streams/dashboard_pipe"
        self.running = True
        self.restart_attempts = 0
        self.max_restarts = 10  # Increase retries to handle intermittent failures
        self.retry_delay = 5  # Delay between retries in seconds
        # Create directory and FIFO pipe if they don't exist
        if not os.path.exists("/tmp/streams"):
            os.makedirs("/tmp/streams")
        if not os.path.exists(self.pipe_path):
            try:
                os.mkfifo(self.pipe_path)
                logging.info(f"FIFO created at {self.pipe_path}")
            except Exception as e:
                logging.error(f"Error creating FIFO pipe: {e}")

    def run(self):
        frame_interval = 1.0 / self.config.get("frame_rate", 6)  # Updated to 6 FPS (~166ms)
        while self.running:
            self.start_ffmpeg()
            try:
                with open(self.pipe_path, "wb") as fifo:
                    logging.info(f"Opened FIFO {self.pipe_path} for writing")
                    while self.running:
                        # Pass width and height from config to render_frame
                        frame = self.renderer.render_frame(self.config["width"], self.config["height"])
                        try:
                            # Convert PIL Image to JPEG bytes for FIFO
                            buf = io.BytesIO()
                            frame.save(buf, format="JPEG", quality=75)
                            fifo.write(buf.getvalue())
                            fifo.flush()
                            logging.debug("Wrote frame to FIFO")
                        except BrokenPipeError as e:
                            logging.error(f"Broken pipe: {e}, restarting FFmpeg")
                            break
                        except Exception as e:
                            logging.error(f"Error writing to FIFO: {e}")
                        time.sleep(frame_interval)
            except Exception as e:
                logging.error(f"Failed to open FIFO or maintain stream: {e}")
            if self.running and self.restart_attempts < self.max_restarts:
                logging.info(
                    f"Waiting {self.retry_delay} seconds before retrying FFmpeg (attempt {self.restart_attempts + 1}/{self.max_restarts})")
                time.sleep(self.retry_delay)
                self.restart_stream()
            else:
                logging.error(f"Max restart attempts ({self.max_restarts}) reached, giving up.")
                self.running = False

    def start_ffmpeg(self):
        rtsp_url = f"rtsp://127.0.0.1:{self.config.get('rtsp_port')}/{self.config.get('stream_name')}"
        cmd = [
            "ffmpeg",
            "-re",  # Read input at native frame rate
            "-f", "image2pipe",  # Input format
            "-framerate", str(self.config.get("frame_rate", 6)),  # Updated to 6 FPS
            "-i", self.pipe_path,  # Input from FIFO pipe
            "-c:v", "libx264",  # Video codec
            "-r", str(self.config.get("frame_rate", 6)),  # Updated to 6 FPS
            "-g", "3",  # GOP size for low latency (1 second at 6 FPS)
            "-preset", "ultrafast",  # Fast encoding
            "-tune", "zerolatency",  # Minimize latency
            "-b:v", "4000k",  # Bitrate
            "-bufsize", "8000k",  # Increased buffer size to handle network jitter
            "-maxrate", "4500k",  # Maximum bitrate
            "-pix_fmt", "yuv420p",  # Pixel format
            "-threads", "2",  # Use 2 threads
            "-s", f"{self.config['width']}x{self.config['height']}",  # Match resolution
            "-timeout", "60000000",  # 60 seconds timeout for input (in microseconds)
            "-stimeout", "60000000",  # 60 seconds socket timeout (in microseconds)
            "-reconnect", "1",  # Enable reconnection on network error
            "-reconnect_at_eof", "1",  # Reconnect at end of file or stream
            "-reconnect_streamed", "1",  # Reconnect for streamed content
            "-reconnect_delay_max", "10",  # Max delay between reconnection attempts (seconds)
            "-f", "rtsp",  # Output format
            "-rtsp_transport", "tcp",  # Use TCP for reliability
            rtsp_url
        ]
        logging.info(f"Starting FFmpeg: {' '.join(cmd)}")
        try:
            self.ffmpeg_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            # Start monitoring FFmpeg in a separate thread
            threading.Thread(target=self.monitor_ffmpeg, daemon=True).start()
            self.restart_attempts = 0  # Reset restart counter on successful start
        except Exception as e:
            logging.error(f"Failed to start FFmpeg: {e}")
            self.restart_stream()

    def monitor_ffmpeg(self):
        """Monitor FFmpeg process and restart if it exits unexpectedly, with detailed logging."""
        if not self.ffmpeg_process:
            return
        while self.running:
            if self.ffmpeg_process.poll() is not None:
                exit_code = self.ffmpeg_process.poll()
                logging.error(f"FFmpeg process exited with code {exit_code}")
                stdout, stderr = self.ffmpeg_process.communicate()
                if stdout:
                    logging.info(f"FFmpeg stdout: {stdout}")
                if stderr:
                    logging.error(f"FFmpeg stderr: {stderr}")
                if self.running and self.restart_attempts < self.max_restarts:
                    self.restart_stream()
                break
            time.sleep(1)  # Check every second

    def restart_stream(self):
        """Restart FFmpeg process if it fails, with increased retry attempts and delay."""
        self.restart_attempts += 1
        if self.restart_attempts >= self.max_restarts:
            logging.error(f"Max restart attempts ({self.max_restarts}) reached, giving up.")
            self.running = False
            return
        if self.ffmpeg_process:
            self.ffmpeg_process.terminate()
            try:
                self.ffmpeg_process.wait(timeout=5)  # Wait up to 5 seconds for termination
            except subprocess.TimeoutExpired:
                self.ffmpeg_process.kill()  # Force kill if it doesn't terminate
                logging.warning("FFmpeg process killed after termination timeout")
            self.ffmpeg_process = None
        logging.info(f"Restarting FFmpeg (attempt {self.restart_attempts}/{self.max_restarts})")
        self.start_ffmpeg()

    def stop(self):
        """Gracefully stop the streamer and FFmpeg process."""
        self.running = False
        if self.ffmpeg_process:
            self.ffmpeg_process.terminate()
            try:
                self.ffmpeg_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ffmpeg_process.kill()
                logging.warning("FFmpeg process killed during shutdown")


# ----------------------
# ONVIF Service
# ----------------------
class OnvifService(threading.Thread):
    def __init__(self, config, server_ip):
        super().__init__()
        self.config = config
        self.server_ip = server_ip
        self.onvif_port = config.get("onvif_port", 8555)
        self.device_info = {
            "Manufacturer": "YoLink",
            "Model": "Dashboard-RTSP",
            "FirmwareVersion": "1.0.0",
            "SerialNumber": str(uuid.uuid4()),
            "HardwareId": "YOLINK-DASHBOARD-1"
        }
        self.rtsp_url = f"rtsp://{server_ip}:{config.get('rtsp_port')}/{config.get('stream_name')}"
        self.daemon = True

    def run(self):
        threading.Thread(target=self.ws_discovery, daemon=True).start()
        logging.info(f"ONVIF service initialized: onvif://{self.server_ip}:{self.onvif_port}")

    def ws_discovery(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("", 3702))
        except Exception as e:
            logging.error(f"WS-Discovery bind error: {e}")
            return
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        logging.info("WS-Discovery listening on UDP 3702")
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                if b"Probe" in data:
                    response = f"""
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
    <a:To>s:Sender</a:To>
  </s:Header>
  <s:Body>
    <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <d:ProbeMatch>
        <a:EndpointReference><a:Address>urn:uuid:{self.device_info['SerialNumber']}</a:Address></a:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:Scopes>onvif://www.onvif.org/name/YoLinkDashboard</d:Scopes>
        <d:XAddrs>http://{self.server_ip}:{self.onvif_port}/onvif/device_service</d:XAddrs>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>
"""
                    sock.sendto(response.encode(), addr)
            except Exception as e:
                logging.error(f"WS-Discovery error: {e}")

    def stop(self):
        pass


# ----------------------
# Flask API Endpoints
# ----------------------
app = Flask(__name__)
renderer = DashboardRenderer(config)
streamer = RtspStreamer(config, renderer)


@app.route('/')
def index():
    return "YoLink RTSP Streamer with ONVIF is running!"


@app.route('/status')
def status():
    stream_url = f"rtsp://{config['server_ip']}:{config['rtsp_port']}/{config['stream_name']}"
    onvif_url = f"onvif://{config['server_ip']}:{config['onvif_port']}" if config.get("enable_onvif") else None
    active_sensors = len([s for s in renderer.sensor_data if "2025" in s.get("last_seen", "")])
    return jsonify({
        "status": "online",
        "sensors": {
            "total": len(renderer.sensor_data),
            "alarmsActive": len(renderer.alarm_sensors),
            "activeSensors": active_sensors
        },
        "stream": {
            "rtspUrl": stream_url,
            "onvifUrl": onvif_url,
            "frameRate": config.get("frame_rate"),
            "resolution": f"{config.get('width')}x{config.get('height')}",
            "currentPage": renderer.current_page + 1,
            "totalPages": renderer.total_pages,
        },
        "system": {
            "uptime": time.time() - os.getpid(),
            "memory": {}
        },
        "lastUpdate": datetime.datetime.now().isoformat()
    })


@app.route('/snapshot')
def snapshot():
    try:
        frame = renderer.render_frame(config['width'], config['height'])  # Updated to include width, height
        # Convert PIL Image to bytes for Response
        buf = io.BytesIO()
        frame.save(buf, format="JPEG", quality=75)
        return Response(buf.getvalue(), mimetype="image/jpeg")
    except Exception as e:
        logging.error(f"Snapshot error: {e}")
        return "Failed to generate snapshot", 500


@app.route('/restart-stream', methods=["POST"])
def restart_stream():
    try:
        streamer.restart_stream()
        return jsonify({
            "success": True,
            "message": "Stream restart initiated",
            "timestamp": datetime.datetime.now().isoformat()
        })
    except Exception as e:
        logging.error(f"Restart stream error: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to restart stream",
            "error": str(e)
        }), 500


@app.route('/sensors')
def sensors():
    sensors_list = []
    for s in renderer.sensor_data:
        sensors_list.append({
            "name": s.get("name"),
            "type": s.get("type"),
            "state": s.get("state"),
            "battery": s.get("battery"),
            "signal": s.get("signal"),
            "last_seen": s.get("last_seen"),
            "temperature": s.get("temperature"),
            "humidity": s.get("humidity")
        })
    return jsonify({
        "count": len(sensors_list),
        "sensors": sensors_list
    })


@app.route('/page/<int:page_num>', methods=["POST"])
def set_page(page_num):
    if page_num < 1 or page_num > renderer.total_pages:
        return jsonify({
            "error": "Invalid page number",
            "valid_range": f"1-{renderer.total_pages}"
        }), 400
    renderer.set_page(page_num - 1)
    return jsonify({
        "success": True,
        "current_page": page_num,
        "totalPages": renderer.total_pages
    })


@app.route('/onvif/device_service', methods=["POST"])
def onvif_device_service():
    soap_action = request.headers.get("SOAPAction", "")
    if "GetDeviceInformation" in soap_action:
        response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Body>
    <GetDeviceInformationResponse xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Manufacturer>YoLink</Manufacturer>
      <Model>Dashboard-RTSP</Model>
      <FirmwareVersion>1.0.0</FirmwareVersion>
      <SerialNumber>{str(uuid.uuid4())}</SerialNumber>
      <HardwareId>YOLINK-DASHBOARD-1</HardwareId>
    </GetDeviceInformationResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""
        return Response(response_xml, mimetype="text/xml")
    elif "GetStreamUri" in soap_action:
        rtsp_url = f"rtsp://{config['server_ip']}:{config['rtsp_port']}/{config['stream_name']}"
        response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Body>
    <GetStreamUriResponse xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Uri>{rtsp_url}</Uri>
      <InvalidAfterConnect>false</InvalidAfterConnect>
      <InvalidAfterReboot>false</InvalidAfterReboot>
      <Timeout>PT0S</Timeout>
    </GetStreamUriResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""
        return Response(response_xml, mimetype="text/xml")
    else:
        return "Unsupported SOAP Action", 400


# ----------------------
# Start Background Services
# ----------------------
def start_background_services():
    ws_url = f"ws://{config['dashboard_url'].replace('http://', '').replace('https://', '')}/ws"
    ws_client = WebSocketClient(ws_url, renderer)
    ws_client.start()
    streamer.start()
    if config.get("enable_onvif"):
        onvif_service = OnvifService(config, config.get("server_ip"))
        onvif_service.start()

    def cycle_pages():
        while True:
            if renderer.total_pages > 1:  # Cycle regardless of alarms
                renderer.set_page((renderer.current_page + 1) % renderer.total_pages)
            time.sleep(config.get("cycle_interval") / 1000.0)

    threading.Thread(target=cycle_pages, daemon=True).start()
    return ws_client


def shutdown(signum, frame):
    logging.info("Shutdown signal received, stopping services...")
    streamer.stop()
    sys.exit(0)


# ----------------------
# Main Entry Point
# ----------------------
if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    ws_client = start_background_services()
    app.run(host="0.0.0.0", port=config.get("http_port"))


def format_smoke_state(state):
    """Format smoke/CO sensor state dictionary."""
    if not isinstance(state, dict):
        return str(state)
    if state.get("smokeAlarm", False):
        return "SMOKE ALARM"
    if state.get("gasAlarm", False):
        return "GAS ALARM"
    if state.get("unexpected", False):
        return "ALERT"
    return "normal"


def map_battery_value(raw_value):
    """Map YoLink battery levels (0-4) to percentages."""
    if not isinstance(raw_value, int) or raw_value < 0 or raw_value > 4:
        return None
    return {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}[raw_value]