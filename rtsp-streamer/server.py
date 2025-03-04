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
import stat

from flask import Flask, request, jsonify, Response
from PIL import Image, ImageDraw, ImageFont
import websocket

# ----------------------
# Logging Configuration
# ----------------------
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

# ----------------------
# Configuration
# ----------------------
config = {
    "dashboard_url": os.environ.get("DASHBOARD_URL", "http://websocket-proxy:3000"),
    "rtsp_port": int(os.environ.get("RTSP_PORT", 8554)),
    "stream_name": os.environ.get("STREAM_NAME", "yolink-dashboard"),
    "frame_rate": int(os.environ.get("FRAME_RATE", 6)),
    "width": int(os.environ.get("WIDTH", 1920)),
    "height": int(os.environ.get("HEIGHT", 1080)),
    "cycle_interval": int(os.environ.get("CYCLE_INTERVAL", 10000)),
    "http_port": int(os.environ.get("RTSP_API_PORT", 3001)),
    "ws_port": int(os.environ.get("WS_PORT", 9999)),
    "enable_onvif": os.environ.get("ENABLE_ONVIF", "true").lower() != "false",
    "onvif_port": int(os.environ.get("ONVIF_PORT", 8555)),
    "server_ip": os.environ.get("SERVER_IP", socket.gethostbyname(socket.gethostname()))
}

# ----------------------
# Helper Functions
# ----------------------
def safe_int(val):
    """Convert value to int safely, returning None if conversion fails."""
    try:
        return int(val)
    except (ValueError, TypeError):
        return None

def safe_float(val):
    """Convert value to float safely, returning None if conversion fails."""
    try:
        return float(val)
    except (ValueError, TypeError):
        return None

def get_text_width(draw, text, font):
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0]

def format_smoke_state(state):
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
    raw_value = safe_int(raw_value)
    if raw_value is None or raw_value < 0 or raw_value > 4:
        return None
    return {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}[raw_value]

# ----------------------
# Dashboard Renderer
# ----------------------
class DashboardRenderer:
    def __init__(self, config):
        self.alarm_display_timer = 0
        self.alarm_display_duration = 30
        self.normal_display_duration = 30
        self.new_alarm_triggered = False
        self.config = config
        self.sensor_data = []
        self.alarm_sensors = []
        self.current_page = 0
        self.total_pages = 1
        self.last_update_time = time.time()
        try:
            self.font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
            self.font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 18)
        except OSError as e:
            logging.warning(f"Could not load DejaVu fonts, using default: {e}")
            self.font_large = ImageFont.load_default()
            self.font_small = ImageFont.load_default()
        self.previous_states = {}

    from datetime import datetime, timedelta

    def update_sensors(self, sensors):
        if not isinstance(sensors, list):
            logging.error("Invalid sensor data: not a list")
            return
        self.sensor_data = []
        self.alarm_sensors = []
        self.last_update_time = time.time()
        logging.info(f"Received {len(sensors)} sensors via WebSocket")

        # Define the cutoff date (60 days ago from today)
        cutoff_date = datetime.now() - timedelta(days=60)

        for s in sensors:
            if not s:
                logging.warning("Skipping empty sensor data")
                continue

            # Extract last_seen and filter out old or never-seen sensors
            last_seen = s.get("last_seen")
            if last_seen == "never":
                logging.debug(f"Filtered out {s.get('name', 'Unknown')} | Last seen: never")
                continue
            try:
                last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                if last_seen_date < cutoff_date:
                    logging.debug(
                        f"Filtered out {s.get('name', 'Unknown')} | Last seen: {last_seen} (older than 60 days)")
                    continue
            except (ValueError, TypeError) as e:
                logging.warning(f"Invalid last_seen format for {s.get('name', 'Unknown')}: {last_seen}, error: {e}")
                continue  # Skip if date parsing fails

            # If we reach here, the sensor is within the last 60 days
            self.sensor_data.append(s)

            # Extract key fields
            sensor_type = s.get("type")
            state = s.get("state")
            signal = safe_int(s.get("signal"))
            battery = safe_int(s.get("battery"))
            name = s.get("name", "Unknown")
            device_id = s.get("deviceId", "UnknownID")

            # Normalize state to string, strip whitespace, and convert to lowercase if it’s not a dict
            state_str = str(state).strip().lower() if state is not None and not isinstance(state, dict) else ""
            logging.debug(
                f"Sensor: {name} | Type: {sensor_type} | Raw State: {state} | Normalized State: {state_str if not isinstance(state, dict) else state} | Signal: {signal} | Battery: {battery} | Last Seen: {last_seen}")

            # Map battery value if present
            mapped_battery = map_battery_value(battery) if battery is not None else None

            # Alarm logic
            is_alarm = False
            alarm_reason = []

            if sensor_type == "DoorSensor":
                if state_str == "open":
                    is_alarm = True
                    alarm_reason.append("State is 'open'")
                if signal is not None and signal < -119:
                    is_alarm = True
                    alarm_reason.append(f"Signal {signal} < -119")
                if mapped_battery is not None and mapped_battery <= 25:
                    is_alarm = True
                    alarm_reason.append(f"Battery {mapped_battery}% <= 25%")
                self.previous_states[device_id] = state_str

            elif sensor_type == "MotionSensor":
                if state_str == "motion":
                    is_alarm = True
                    alarm_reason.append("State is 'motion'")
                if signal is not None and signal < -119:
                    is_alarm = True
                    alarm_reason.append(f"Signal {signal} < -119")
                if mapped_battery is not None and mapped_battery <= 25:
                    is_alarm = True
                    alarm_reason.append(f"Battery {mapped_battery}% <= 25%")

            elif sensor_type in ["THSensor", "COSmokeSensor"]:
                if isinstance(state, dict):
                    alarms = state
                    if any(alarms.get(key, False) for key in ["smokeAlarm", "gasAlarm", "unexpected", "highTempAlarm"]):
                        is_alarm = True
                        alarm_reason.append(f"Alarm state active: {alarms}")
                if mapped_battery is not None and mapped_battery <= 25:
                    is_alarm = True
                    alarm_reason.append(f"Battery {mapped_battery}% <= 25%")
                if signal is not None and signal < -119:
                    is_alarm = True
                    alarm_reason.append(f"Signal {signal} < -119")

            elif sensor_type in ["Outlet", "MultiOutlet"]:
                logging.debug(
                    f"Outlet/MultiOutlet {name} processed: State={state_str if not isinstance(state, dict) else state}")

            # Add to alarm list if applicable
            if is_alarm:
                self.alarm_sensors.append(s)
                logging.debug(f"Added to alarms: {name} | Reasons: {', '.join(alarm_reason)}")
            else:
                logging.debug(f"Not alarmed: {name} | No conditions met")

        # Log the final alarm sensors list
        alarm_names = [s.get("name", "Unknown") for s in self.alarm_sensors]
        logging.info(f"Sensors in alarm: {alarm_names} (Total: {len(self.alarm_sensors)})")

        # Update pagination
        sensors_per_page = 20
        self.total_pages = max(1, (len(self.sensor_data) + sensors_per_page - 1) // sensors_per_page)
        if self.current_page >= self.total_pages:
            self.current_page = 0
        logging.info(
            f"Updated: {len(self.sensor_data)} sensors, {len(self.alarm_sensors)} alarms, {self.total_pages} pages")

        # Trigger alarm view if new alarms detected
        if self.alarm_sensors and not self.new_alarm_triggered:
            self.new_alarm_triggered = True
            self.alarm_display_timer = time.time()

    def render_alarm_view(self, draw):
        # Draw red banner at the top
        draw.rectangle([(0, 0), (draw.im.size[0], 50)], fill="#ff0000")
        draw.text((10, 10), "SENSORS IN ALARM", font=self.font_large, fill="#ffffff")

        # Calculate and display summary on the banner
        active_count = len(self.sensor_data)
        alarm_count = len(self.alarm_sensors)
        summary_text = f"Active Sensors: {active_count} | Sensors in Alarm: {alarm_count}"
        text_width = get_text_width(draw, summary_text, self.font_small)
        draw.text((draw.im.size[0] - text_width - 10, 10), summary_text, font=self.font_small, fill="#ffffff")

        # Handle case with no alarm sensors
        if not self.alarm_sensors:
            draw.text((10, 60), "No sensors in alarm", font=self.font_small, fill="#ffffff")
            return

        # Render up to 20 alarm sensors in a 5-column grid
        sensors_per_page = 20
        for i, sensor in enumerate(self.alarm_sensors[:sensors_per_page]):
            x = 10 + (i % 5) * 380
            y = 60 + (i // 5) * 260
            draw.rectangle([(x, y), (x + 370, y + 250)], outline="#ffffff")
            draw.text((x + 10, y + 10), sensor.get("name", "Unknown"), font=self.font_small, fill="#ffffff")

            sensor_type = sensor.get("type")
            state = sensor.get("state", "N/A")

            # Handle outlets differently: show status based on power
            if sensor_type in ["Outlet", "MultiOutlet"]:
                if "power" in sensor:
                    power = safe_float(sensor["power"])
                    if power is not None:
                        status = "On" if power > 0 else "Off"
                        draw.text((x + 10, y + 30), f"Status: {status} ({power}W)", font=self.font_small,
                                  fill="#ffffff")
                    else:
                        draw.text((x + 10, y + 30), "Status: Unknown", font=self.font_small, fill="#ffffff")
                    y_offset = 50
                elif "powers" in sensor and isinstance(sensor["powers"], list):
                    powers = sensor["powers"]
                    for j, power in enumerate(powers[:2]):
                        power_val = safe_float(power)
                        if power_val is not None:
                            status = "On" if power_val > 0 else "Off"
                            draw.text((x + 10, y + 30 + j * 20), f"Outlet {j + 1}: {status} ({power_val}W)",
                                      font=self.font_small, fill="#ffffff")
                        else:
                            draw.text((x + 10, y + 30 + j * 20), f"Outlet {j + 1}: Unknown",
                                      font=self.font_small, fill="#ffffff")
                    y_offset = 50 + (len(powers[:2]) * 20)
                else:
                    draw.text((x + 10, y + 30), "Status: Unknown", font=self.font_small, fill="#ffffff")
                    y_offset = 50
            else:
                # For non-outlet sensors, display the state as is
                if sensor_type == "THSensor" and isinstance(state, dict):
                    state_text = format_smoke_state(state)
                else:
                    state_text = state
                draw.text((x + 10, y + 30), f"State: {state_text}", font=self.font_small, fill="#ffffff")
                y_offset = 50

            # Additional sensor-specific details
            if sensor_type in ["MotionSensor", "ContactSensor"]:
                if "battery" in sensor and sensor["battery"] is not None:
                    battery_value = map_battery_value(safe_int(sensor["battery"]))
                    if battery_value is not None:
                        draw.text((x + 10, y + y_offset), f"Battery: {battery_value}%", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
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
                    battery_value = map_battery_value(safe_int(sensor["battery"]))
                    if battery_value is not None:
                        draw.text((x + 10, y + y_offset), f"Battery: {battery_value}%", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
            elif sensor_type in ["Outlet", "MultiOutlet"]:
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20

    def render_frame(self, width, height):
        current_time = time.time()
        image = Image.new("RGB", (width, height), "#000000")
        draw = ImageDraw.Draw(image)

        if self.alarm_sensors and (current_time - self.alarm_display_timer < self.alarm_display_duration):
            self.render_alarm_view(draw)
            logging.debug("Rendering alarm view")
        elif current_time - self.alarm_display_timer < self.alarm_display_duration + self.normal_display_duration:
            self.render_normal_view(draw)
            logging.debug("Rendering normal view")
        else:
            self.alarm_display_timer = 0
            self.new_alarm_triggered = False
            self.render_normal_view(draw)
            logging.debug("Rendering default normal view")

        return image

    def render_normal_view(self, draw):
        # Draw gray banner at the top
        draw.rectangle([(0, 0), (draw.im.size[0], 50)], fill="#333333")
        draw.text((10, 10), "SENSORS", font=self.font_large, fill="#ffffff")

        # Calculate and display summary on the banner
        active_count = len(self.sensor_data)
        alarm_count = len(self.alarm_sensors)
        summary_text = f"Active Sensors: {active_count} | Sensors in Alarm: {alarm_count}"
        text_width = get_text_width(draw, summary_text, self.font_small)
        draw.text((draw.im.size[0] - text_width - 10, 10), summary_text, font=self.font_small, fill="#ffffff")

        # Handle case with no sensor data
        if not self.sensor_data:
            draw.text((10, 60), "No sensor data available", font=self.font_small, fill="#ffffff")
            return

        # Pagination logic: 20 sensors per page
        sensors_per_page = 20
        start_idx = self.current_page * sensors_per_page
        end_idx = min(start_idx + sensors_per_page, len(self.sensor_data))
        sensors_to_show = self.sensor_data[start_idx:end_idx]

        # Render each sensor in a 5-column grid
        for i, sensor in enumerate(sensors_to_show):
            x = 10 + (i % 5) * 380
            y = 60 + (i // 5) * 260
            draw.rectangle([(x, y), (x + 370, y + 250)], outline="#ffffff")
            draw.text((x + 10, y + 10), sensor.get("name", "Unknown"), font=self.font_small, fill="#ffffff")

            sensor_type = sensor.get("type")
            state = sensor.get("state", "N/A")

            # Handle outlets differently: show status based on power
            if sensor_type in ["Outlet", "MultiOutlet"]:
                if "power" in sensor:
                    power = safe_float(sensor["power"])
                    if power is not None:
                        status = "On" if power > 0 else "Off"
                        draw.text((x + 10, y + 30), f"Status: {status} ({power}W)", font=self.font_small,
                                  fill="#ffffff")
                    else:
                        draw.text((x + 10, y + 30), "Status: Unknown", font=self.font_small, fill="#ffffff")
                    y_offset = 50
                elif "powers" in sensor and isinstance(sensor["powers"], list):
                    powers = sensor["powers"]
                    for j, power in enumerate(powers[:2]):
                        power_val = safe_float(power)
                        if power_val is not None:
                            status = "On" if power_val > 0 else "Off"
                            draw.text((x + 10, y + 30 + j * 20), f"Outlet {j + 1}: {status} ({power_val}W)",
                                      font=self.font_small, fill="#ffffff")
                        else:
                            draw.text((x + 10, y + 30 + j * 20), f"Outlet {j + 1}: Unknown",
                                      font=self.font_small, fill="#ffffff")
                    y_offset = 50 + (len(powers[:2]) * 20)
                else:
                    draw.text((x + 10, y + 30), "Status: Unknown", font=self.font_small, fill="#ffffff")
                    y_offset = 50
            else:
                # For non-outlet sensors, display the state as is
                if sensor_type == "THSensor" and isinstance(state, dict):
                    state_text = format_smoke_state(state)
                else:
                    state_text = state
                draw.text((x + 10, y + 30), f"State: {state_text}", font=self.font_small, fill="#ffffff")
                y_offset = 50

            # Additional sensor-specific details
            if sensor_type in ["MotionSensor", "ContactSensor"]:
                if "battery" in sensor and sensor["battery"] is not None:
                    battery_value = map_battery_value(safe_int(sensor["battery"]))
                    if battery_value is not None:
                        draw.text((x + 10, y + y_offset), f"Battery: {battery_value}%", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
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
                    battery_value = map_battery_value(safe_int(sensor["battery"]))
                    if battery_value is not None:
                        draw.text((x + 10, y + y_offset), f"Battery: {battery_value}%", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
            elif sensor_type in ["Outlet", "MultiOutlet"]:
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20

    def render_alarm_view(self, draw):
        # Draw red banner at the top
        draw.rectangle([(0, 0), (draw.im.size[0], 50)], fill="#ff0000")
        draw.text((10, 10), "SENSORS IN ALARM", font=self.font_large, fill="#ffffff")

        # Calculate and display summary on the banner
        active_count = len(self.sensor_data)
        alarm_count = len(self.alarm_sensors)
        summary_text = f"Active Sensors: {active_count} | Sensors in Alarm: {alarm_count}"
        text_width = get_text_width(draw, summary_text, self.font_small)
        draw.text((draw.im.size[0] - text_width - 10, 10), summary_text, font=self.font_small, fill="#ffffff")

        # Handle case with no alarm sensors
        if not self.alarm_sensors:
            draw.text((10, 60), "No sensors in alarm", font=self.font_small, fill="#ffffff")
            return

        # Render up to 20 alarm sensors in a 5-column grid
        sensors_per_page = 20
        for i, sensor in enumerate(self.alarm_sensors[:sensors_per_page]):
            x = 10 + (i % 5) * 380
            y = 60 + (i // 5) * 260
            draw.rectangle([(x, y), (x + 370, y + 250)], outline="#ffffff")
            draw.text((x + 10, y + 10), sensor.get("name", "Unknown"), font=self.font_small, fill="#ffffff")

            sensor_type = sensor.get("type")
            state = sensor.get("state", "N/A")

            # Handle outlets differently: show status based on power
            if sensor_type in ["Outlet", "MultiOutlet"]:
                if "power" in sensor:
                    power = safe_float(sensor["power"])
                    if power is not None:
                        status = "On" if power > 0 else "Off"
                        draw.text((x + 10, y + 30), f"Status: {status} ({power}W)", font=self.font_small,
                                  fill="#ffffff")
                    else:
                        draw.text((x + 10, y + 30), "Status: Unknown", font=self.font_small, fill="#ffffff")
                    y_offset = 50
                elif "powers" in sensor and isinstance(sensor["powers"], list):
                    powers = sensor["powers"]
                    for j, power in enumerate(powers[:2]):
                        power_val = safe_float(power)
                        if power_val is not None:
                            status = "On" if power_val > 0 else "Off"
                            draw.text((x + 10, y + 30 + j * 20), f"Outlet {j + 1}: {status} ({power_val}W)",
                                      font=self.font_small, fill="#ffffff")
                        else:
                            draw.text((x + 10, y + 30 + j * 20), f"Outlet {j + 1}: Unknown",
                                      font=self.font_small, fill="#ffffff")
                    y_offset = 50 + (len(powers[:2]) * 20)
                else:
                    draw.text((x + 10, y + 30), "Status: Unknown", font=self.font_small, fill="#ffffff")
                    y_offset = 50
            else:
                # For non-outlet sensors, display the state as is
                if sensor_type == "THSensor" and isinstance(state, dict):
                    state_text = format_smoke_state(state)
                else:
                    state_text = state
                draw.text((x + 10, y + 30), f"State: {state_text}", font=self.font_small, fill="#ffffff")
                y_offset = 50

            # Additional sensor-specific details
            if sensor_type in ["MotionSensor", "ContactSensor"]:
                if "battery" in sensor and sensor["battery"] is not None:
                    battery_value = map_battery_value(safe_int(sensor["battery"]))
                    if battery_value is not None:
                        draw.text((x + 10, y + y_offset), f"Battery: {battery_value}%", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
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
                    battery_value = map_battery_value(safe_int(sensor["battery"]))
                    if battery_value is not None:
                        draw.text((x + 10, y + y_offset), f"Battery: {battery_value}%", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20
            elif sensor_type in ["Outlet", "MultiOutlet"]:
                if "signal" in sensor:
                    signal_value = safe_int(sensor["signal"])
                    if signal_value is not None:
                        draw.text((x + 10, y + y_offset), f"Signal: {signal_value}", font=self.font_small,
                                  fill="#ffffff")
                        y_offset += 20

    def set_page(self, page_num):
        if 0 <= page_num < self.total_pages:
            self.current_page = page_num
            logging.info(f"Set page to {page_num + 1}/{self.total_pages}")
        else:
            logging.warning(f"Attempted to set invalid page {page_num + 1}, valid range: 1-{self.total_pages}")

# ----------------------
# WebSocket Client
# ----------------------
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
                logging.info(f"Attempting to connect to WebSocket: {self.url}")
                self.ws = websocket.create_connection(self.url)
                logging.info(f"Connected to WebSocket: {self.url}")
                while True:
                    try:
                        msg = self.ws.recv()
                        logging.debug(f"Received WebSocket message: {msg}")
                        try:
                            data = json.loads(msg)
                            if data.get("type") == "sensors-update":
                                sensors = data.get("sensors", [])
                                logging.info(f"Received {len(sensors)} sensors via WebSocket")
                                self.renderer.update_sensors(sensors)
                            else:
                                logging.debug(f"Ignored message type: {data.get('type')}")
                        except json.JSONDecodeError as e:
                            logging.error(f"Invalid JSON in WebSocket message: {e}. Raw message: {msg}")
                            continue
                    except Exception as e:
                        logging.error(f"Error processing WebSocket message: {e}")
                        break
            except Exception as e:
                logging.error(f"WebSocket connection failed: {e}")
                time.sleep(2)

    def close(self):
        if self.ws:
            self.ws.close()

# ----------------------
# RTSP Streamer
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
        self.max_restarts = 10
        self.retry_delay = 5
        if not os.path.exists("/tmp/streams"):
            os.makedirs("/tmp/streams")
        if os.path.exists(self.pipe_path) and not stat.S_ISFIFO(os.stat(self.pipe_path).st_mode):
            os.remove(self.pipe_path)
            os.mkfifo(self.pipe_path)
            logging.info(f"Recreated FIFO at {self.pipe_path}")
        elif not os.path.exists(self.pipe_path):
            os.mkfifo(self.pipe_path)
            logging.info(f"Created FIFO at {self.pipe_path}")

    def run(self):
        frame_interval = 1.0 / self.config.get("frame_rate", 6)
        while self.running:
            self.start_ffmpeg()
            try:
                with open(self.pipe_path, "wb") as fifo:
                    logging.info(f"Opened FIFO {self.pipe_path} for writing")
                    while self.running:
                        frame = self.renderer.render_frame(self.config["width"], self.config["height"])
                        try:
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
                logging.info(f"Waiting {self.retry_delay} seconds before retrying FFmpeg (attempt {self.restart_attempts + 1}/{self.max_restarts})")
                time.sleep(self.retry_delay)
                self.restart_stream()
            else:
                logging.error(f"Max restart attempts ({self.max_restarts}) reached, giving up.")
                self.running = False

    def start_ffmpeg(self):
        rtsp_url = f"rtsp://127.0.0.1:{self.config.get('rtsp_port')}/{self.config.get('stream_name')}"
        cmd = [
            "ffmpeg",
            "-re",
            "-f", "image2pipe",
            "-framerate", str(self.config.get("frame_rate", 6)),
            "-i", self.pipe_path,
            "-c:v", "libx264",
            "-r", str(self.config.get("frame_rate", 6)),
            "-g", "12",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-b:v", "4000k",
            "-bufsize", "8000k",
            "-maxrate", "4500k",
            "-pix_fmt", "yuv420p",
            "-threads", "2",
            "-s", f"{self.config['width']}x{self.config['height']}",
            "-timeout", "60000000",
            "-reconnect", "1",
            "-reconnect_at_eof", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "10",
            "-f", "rtsp",
            "-rtsp_transport", "tcp",
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
            stderr_line = self.ffmpeg_process.stderr.readline()
            if stderr_line:
                logging.info(f"FFmpeg initial output: {stderr_line.strip()}")
            threading.Thread(target=self.monitor_ffmpeg, daemon=True).start()
            self.restart_attempts = 0
        except Exception as e:
            logging.error(f"Failed to start FFmpeg: {e}")
            self.restart_stream()

    def monitor_ffmpeg(self):
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
            time.sleep(1)

    def restart_stream(self):
        self.restart_attempts += 1
        if self.restart_attempts >= self.max_restarts:
            logging.error(f"Max restart attempts ({self.max_restarts}) reached, giving up.")
            self.running = False
            return
        if self.ffmpeg_process:
            self.ffmpeg_process.terminate()
            try:
                self.ffmpeg_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ffmpeg_process.kill()
                logging.warning("FFmpeg process killed after termination timeout")
            self.ffmpeg_process = None
        logging.info(f"Restarting FFmpeg (attempt {self.restart_attempts}/{self.max_restarts})")
        self.start_ffmpeg()

    def stop(self):
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
        frame = renderer.render_frame(config['width'], config['height'])
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
    page_num -= 1
    if page_num < 0 or page_num >= renderer.total_pages:
        return jsonify({
            "error": "Invalid page number",
            "valid_range": f"1-{renderer.total_pages}"
        }), 400
    renderer.set_page(page_num)
    return jsonify({
        "success": True,
        "current_page": page_num + 1,
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
            if renderer.total_pages > 1:
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