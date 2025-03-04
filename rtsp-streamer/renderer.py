"""
Dashboard UI rendering for the YoLink Dashboard RTSP Server.
"""
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from PIL import Image, ImageDraw

from app.utils.data import safe_int, safe_float, map_battery_value, format_smoke_state
from app.utils.image import get_text_width, load_fonts

logger = logging.getLogger(__name__)


class DashboardRenderer:
    """
    Renders the dashboard UI with sensor information.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the dashboard renderer.

        Args:
            config: Application configuration
        """
        self.config = config
        self.sensor_data = []
        self.alarm_sensors = []
        self.current_page = 0
        self.total_pages = 1
        self.last_update_time = time.time()

        # Alarm display settings
        self.alarm_display_timer = 0
        self.alarm_display_duration = 30
        self.normal_display_duration = 30
        self.new_alarm_triggered = False
        self.previous_states = {}

        # Load fonts
        self.font_large, self.font_small = load_fonts()

    def update_sensors(self, sensors: List[Dict[str, Any]]) -> None:
        """
        Update the sensor data and determine which sensors are in alarm state.

        Args:
            sensors: List of sensor data dictionaries
        """
        if not isinstance(sensors, list):
            logger.error("Invalid sensor data: not a list")
            return

        self.sensor_data = []
        self.alarm_sensors = []
        self.last_update_time = time.time()
        logger.info(f"Received {len(sensors)} sensors via WebSocket")

        # Define the cutoff date (60 days ago from today)
        cutoff_date = datetime.now() - timedelta(days=60)

        for s in sensors:
            if not s:
                logger.warning("Skipping empty sensor data")
                continue

            # Extract last_seen and filter out old or never-seen sensors
            last_seen = s.get("last_seen")
            if last_seen == "never":
                logger.debug(f"Filtered out {s.get('name', 'Unknown')} | Last seen: never")
                continue

            try:
                last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                if last_seen_date < cutoff_date:
                    logger.debug(
                        f"Filtered out {s.get('name', 'Unknown')} | Last seen: {last_seen} (older than 60 days)")
                    continue
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid last_seen format for {s.get('name', 'Unknown')}: {last_seen}, error: {e}")
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

            # Normalize state to string, strip whitespace, and convert to lowercase if it's not a dict
            state_str = str(state).strip().lower() if state is not None and not isinstance(state, dict) else ""
            logger.debug(
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
                logger.debug(
                    f"Outlet/MultiOutlet {name} processed: State={state_str if not isinstance(state, dict) else state}")

            # Add to alarm list if applicable
            if is_alarm:
                self.alarm_sensors.append(s)
                logger.debug(f"Added to alarms: {name} | Reasons: {', '.join(alarm_reason)}")
            else:
                logger.debug(f"Not alarmed: {name} | No conditions met")

        # Log the final alarm sensors list
        alarm_names = [s.get("name", "Unknown") for s in self.alarm_sensors]
        logger.info(f"Sensors in alarm: {alarm_names} (Total: {len(self.alarm_sensors)})")

        # Update pagination
        sensors_per_page = 20
        self.total_pages = max(1, (len(self.sensor_data) + sensors_per_page - 1) // sensors_per_page)
        if self.current_page >= self.total_pages:
            self.current_page = 0
        logger.info(
            f"Updated: {len(self.sensor_data)} sensors, {len(self.alarm_sensors)} alarms, {self.total_pages} pages")

        # Trigger alarm view if new alarms detected
        if self.alarm_sensors and not self.new_alarm_triggered:
            self.new_alarm_triggered = True
            self.alarm_display_timer = time.time()

    def set_page(self, page_num: int) -> None:
        """
        Set the current page number for pagination.

        Args:
            page_num: Page number (0-based)
        """
        if 0 <= page_num < self.total_pages:
            self.current_page = page_num
            logger.info(f"Set page to {page_num + 1}/{self.total_pages}")
        else:
            logger.warning(f"Attempted to set invalid page {page_num + 1}, valid range: 1-{self.total_pages}")

    def render_frame(self, width: int, height: int) -> Image.Image:
        """
        Render a frame of the dashboard.

        Args:
            width: Frame width in pixels
            height: Frame height in pixels

        Returns:
            PIL.Image: Rendered frame
        """
        current_time = time.time()
        image = Image.new("RGB", (width, height), "#000000")
        draw = ImageDraw.Draw(image)

        if self.alarm_sensors and (current_time - self.alarm_display_timer < self.alarm_display_duration):
            self._render_alarm_view(draw)
            logger.debug("Rendering alarm view")
        elif current_time - self.alarm_display_timer < self.alarm_display_duration + self.normal_display_duration:
            self._render_normal_view(draw)
            logger.debug("Rendering normal view")
        else:
            self.alarm_display_timer = 0
            self.new_alarm_triggered = False
            self._render_normal_view(draw)
            logger.debug("Rendering default normal view")

        return image

    def _render_sensor_details(self, draw: ImageDraw.ImageDraw, sensor: Dict[str, Any],
                               x: int, y: int, y_offset: int = 50) -> None:
        """
        Render sensor details in a sensor panel.

        Args:
            draw: PIL ImageDraw object
            sensor: Sensor data dictionary
            x: X-coordinate of the sensor panel
            y: Y-coordinate of the sensor panel
            y_offset: Starting Y-offset for additional details

        Returns:
            None
        """
        sensor_type = sensor.get("type")

        # Draw common sensor details based on sensor type
        if sensor_type in ["MotionSensor", "ContactSensor", "DoorSensor"]:
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

    def _render_sensor_panel(self, draw: ImageDraw.ImageDraw, sensor: Dict[str, Any],
                             x: int, y: int) -> None:
        """
        Render a single sensor panel.

        Args:
            draw: PIL ImageDraw object
            sensor: Sensor data dictionary
            x: X-coordinate of the sensor panel
            y: Y-coordinate of the sensor panel

        Returns:
            None
        """
        # Draw panel outline
        draw.rectangle([(x, y), (x + 370, y + 250)], outline="#ffffff")

        # Draw sensor name
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

        # Render additional sensor details
        self._render_sensor_details(draw, sensor, x, y, y_offset)

    def _render_normal_view(self, draw: ImageDraw.ImageDraw) -> None:
        """
        Render the normal view of the dashboard.

        Args:
            draw: PIL ImageDraw object

        Returns:
            None
        """
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
            self._render_sensor_panel(draw, sensor, x, y)

    def _render_alarm_view(self, draw: ImageDraw.ImageDraw) -> None:
        """
        Render the alarm view of the dashboard.

        Args:
            draw: PIL ImageDraw object

        Returns:
            None
        """
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
            self._render_sensor_panel(draw, sensor, x, y)