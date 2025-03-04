"""
Enhanced Dashboard UI rendering for the YoLink Dashboard RTSP Server.
Supports multiple resolutions with appropriate layouts, alarm highlighting,
and update time indicators for improved readability.
"""
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from PIL import Image, ImageDraw, ImageFont

from data import safe_int, safe_float, map_battery_value, format_smoke_state
from image import load_fonts

logger = logging.getLogger(__name__)


class DashboardRenderer:
    """
    Renders the dashboard UI with sensor information.
    Supports multiple resolutions with appropriate layouts.
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
        self.alarm_display_duration = 30  # Increased to 30 seconds (was variable in config)
        self.normal_display_duration = 30
        self.new_alarm_triggered = False
        self.previous_states = {}
        self.newest_alarm_id = None  # Track the newest alarm for highlighting

        # Default resolution values
        self.current_width = config.get("width", 1920)
        self.current_height = config.get("height", 1080)
        self.sensors_per_page = config.get("sensors_per_page", 20)

        # Layout parameters based on resolution
        self.layout_params = self._calc_layout_params()

        # Load fonts
        self.fonts = self._load_fonts_for_resolution()

    def _load_fonts_for_resolution(self) -> Dict[str, ImageFont.FreeTypeFont]:
        """
        Load appropriate fonts based on the current resolution.
        Increased font sizes for better readability on mobile devices.

        Returns:
            Dict[str, ImageFont.FreeTypeFont]: Dictionary of font objects
        """
        # Increased base font sizes significantly for better readability
        base_font_size = max(18, int(self.current_height / 36))  # Was /54, now /36
        title_font_size = max(28, int(self.current_height / 20))  # Was /30, now /20

        # Add an extra large font for critical information
        xl_font_size = max(36, int(self.current_height / 15))

        try:
            fonts = {
                "xl": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", xl_font_size),
                "large": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", title_font_size),
                "medium": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", base_font_size + 6),
                "small": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", base_font_size)
            }
        except OSError as e:
            logger.warning(f"Could not load DejaVu fonts, using default: {e}")
            fonts = {
                "xl": ImageFont.load_default(),
                "large": ImageFont.load_default(),
                "medium": ImageFont.load_default(),
                "small": ImageFont.load_default()
            }

        logger.info(f"Loaded fonts - XL: {xl_font_size}px, Large: {title_font_size}px, Medium: {base_font_size+6}px, Small: {base_font_size}px")
        return fonts

    def _calc_layout_params(self) -> Dict[str, Any]:
        """
        Calculate layout parameters based on current resolution.
        Adjusted for larger fonts and better readability.

        Returns:
            Dict[str, Any]: Layout parameters
        """
        # Base everything on relative proportions of the screen
        width, height = self.current_width, self.current_height

        # Increase banner height for larger text
        banner_height = max(60, min(80, height // 12))  # Was //18, now //12

        # Calculate the grid size based on sensors_per_page
        grid_cols = min(5, max(1, int(self.sensors_per_page ** 0.5)))
        grid_rows = (self.sensors_per_page + grid_cols - 1) // grid_cols

        # Panel size calculated relative to screen size and grid dimensions
        panel_width = max(280, (width - (grid_cols + 1) * 15) // grid_cols)  # Wider panels
        panel_height = max(180, (height - banner_height - (grid_rows + 1) * 15) // grid_rows)  # Taller panels

        return {
            "grid_cols": grid_cols,
            "grid_rows": grid_rows,
            "panel_width": panel_width,
            "panel_height": panel_height,
            "banner_height": banner_height,
            "padding": max(8, min(20, height // 72)),  # Increased padding
            "title_height": max(30, min(40, height // 27)),  # Taller title section
            "sensor_row_height": max(24, min(32, height // 34)),  # Taller rows for more readable text
        }

    def set_resolution(self, width: int, height: int, sensors_per_page: Optional[int] = None) -> None:
        """
        Update the renderer's resolution and adjust layout accordingly.

        Args:
            width: New width in pixels
            height: New height in pixels
            sensors_per_page: Optional explicit sensors per page override
        """
        if width == self.current_width and height == self.current_height and (
            sensors_per_page is None or sensors_per_page == self.sensors_per_page):
            # No change in resolution or sensors_per_page, skip recalculation
            return

        self.current_width = width
        self.current_height = height

        # Update sensors per page if specified or calculate based on resolution
        if sensors_per_page is not None:
            self.sensors_per_page = sensors_per_page
        else:
            # Calculate appropriate number based on resolution
            if width >= 1920 and height >= 1080:
                self.sensors_per_page = 20  # Full HD
            elif width >= 1280 and height >= 720:
                self.sensors_per_page = 12  # HD
            elif width >= 960 and height >= 540:
                self.sensors_per_page = 6  # qHD
            else:
                self.sensors_per_page = 4  # Low resolution

        # Update layout parameters for new resolution
        self.layout_params = self._calc_layout_params()

        # Reload fonts appropriate for this resolution
        self.fonts = self._load_fonts_for_resolution()

        # Recalculate pagination
        self._update_pagination()

        logger.info(f"Renderer resolution set to {width}x{height} with {self.sensors_per_page} sensors per page")

    def _update_pagination(self) -> None:
        """
        Update pagination based on current sensors_per_page.
        """
        total_sensors = len(self.sensor_data)
        self.total_pages = max(1, (total_sensors + self.sensors_per_page - 1) // self.sensors_per_page)

        # Adjust current page if it's now out of bounds
        if self.current_page >= self.total_pages:
            self.current_page = 0

        logger.debug(f"Pagination updated: {total_sensors} sensors, {self.total_pages} pages")

    def _format_time_since_update(self) -> str:
        """
        Format the time since the last sensor update in a human-readable way.

        Returns:
            str: Formatted time string (e.g., "Updated 2m ago" or "Updated just now")
        """
        if not hasattr(self, 'last_update_time'):
            return "No updates yet"

        elapsed_seconds = time.time() - self.last_update_time

        if elapsed_seconds < 60:
            return "Updated just now"
        elif elapsed_seconds < 3600:
            minutes = int(elapsed_seconds / 60)
            return f"Updated {minutes}m ago"
        elif elapsed_seconds < 86400:
            hours = int(elapsed_seconds / 3600)
            return f"Updated {hours}h ago"
        else:
            days = int(elapsed_seconds / 86400)
            return f"Updated {days}d ago"

    def update_sensors(self, sensors: List[Dict[str, Any]]) -> None:
        """
        Update the sensor data and determine which sensors are in alarm state.
        Detects new alarms for immediate display.

        Args:
            sensors: List of sensor data dictionaries
        """
        if not isinstance(sensors, list):
            logger.error("Invalid sensor data: not a list")
            return

        # Track previous alarm sensors to detect new alarms
        previous_alarm_ids = set(s.get("deviceId") for s in self.alarm_sensors if s.get("deviceId"))

        # Reset for new data
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

        # Get current alarm IDs
        current_alarm_ids = set(s.get("deviceId") for s in self.alarm_sensors if s.get("deviceId"))

        # Detect new alarms
        new_alarm_ids = current_alarm_ids - previous_alarm_ids

        # If there are new alarms, trigger alarm view and track newest for highlighting
        if new_alarm_ids:
            self.new_alarm_triggered = True
            self.alarm_display_timer = time.time()
            self.newest_alarm_id = next(iter(new_alarm_ids))  # Use first new alarm ID

            # Find and log newest alarm name
            for s in self.alarm_sensors:
                if s.get("deviceId") == self.newest_alarm_id:
                    logger.info(f"New alarm highlighted: {s.get('name', 'Unknown')} (ID: {self.newest_alarm_id})")
                    break

        # Log the final alarm sensors list
        alarm_names = [s.get("name", "Unknown") for s in self.alarm_sensors]
        logger.info(f"Sensors in alarm: {alarm_names} (Total: {len(self.alarm_sensors)})")

        # Update pagination based on the current sensors_per_page
        self._update_pagination()

        logger.info(
            f"Updated: {len(self.sensor_data)} sensors, {len(self.alarm_sensors)} alarms, {self.total_pages} pages")

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
        # Update resolution and layout if different from current
        if width != self.current_width or height != self.current_height:
            self.set_resolution(width, height)

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
            self.newest_alarm_id = None  # Clear newest alarm when returning to normal view
            self._render_normal_view(draw)
            logger.debug("Rendering default normal view")

        return image

    def _get_text_width(self, draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont) -> int:
        """
        Calculate the width of text with a given font.

        Args:
            draw: PIL ImageDraw object
            text: Text to measure
            font: Font to use for measurement

        Returns:
            int: Width of text in pixels
        """
        bbox = draw.textbbox((0, 0), text, font=font)
        return bbox[2] - bbox[0]

    def _truncate_text(self, draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont, max_width: int) -> str:
        """
        Truncate text to fit within a maximum width.

        Args:
            draw: PIL ImageDraw object
            text: Text to truncate
            font: Font to use for measurement
            max_width: Maximum width in pixels

        Returns:
            str: Truncated text with ellipsis if needed
        """
        if not text:
            return ""

        if self._get_text_width(draw, text, font) <= max_width:
            return text

        ellipsis = "..."
        ellipsis_width = self._get_text_width(draw, ellipsis, font)

        # If even the ellipsis is too wide, return empty string
        if ellipsis_width > max_width:
            return ""

        # Try removing characters until it fits
        result = text
        while len(result) > 1 and self._get_text_width(draw, result + ellipsis, font) > max_width:
            result = result[:-1]

        return result + ellipsis

    def _render_sensor_details(self, draw: ImageDraw.ImageDraw, sensor: Dict[str, Any],
                               x: int, y: int, panel_width: int, y_offset: int = 50) -> None:
        """
        Render sensor details in a sensor panel.

        Args:
            draw: PIL ImageDraw object
            sensor: Sensor data dictionary
            x: X-coordinate of the sensor panel
            y: Y-coordinate of the sensor panel
            panel_width: Width of the panel in pixels
            y_offset: Starting Y-offset for additional details

        Returns:
            None
        """
        padding = self.layout_params["padding"]
        row_height = self.layout_params["sensor_row_height"]
        max_text_width = panel_width - (padding * 2)

        sensor_type = sensor.get("type")

        # Draw common sensor details based on sensor type
        if sensor_type in ["MotionSensor", "ContactSensor", "DoorSensor"]:
            if "battery" in sensor and sensor["battery"] is not None:
                battery_value = map_battery_value(safe_int(sensor["battery"]))
                if battery_value is not None:
                    # Colorize battery level
                    if battery_value <= 25:
                        batt_color = "#ff5555"  # Critical - red
                    elif battery_value <= 50:
                        batt_color = "#ffff55"  # Low - yellow
                    else:
                        batt_color = "#ffffff"  # Good - white

                    batt_text = f"Battery: {battery_value}%"
                    draw.text((x + padding, y + y_offset), batt_text, font=self.fonts["medium"],
                              fill=batt_color)
                    y_offset += row_height

            if "signal" in sensor:
                signal_value = safe_int(sensor["signal"])
                if signal_value is not None:
                    # Colorize signal strength
                    if signal_value < -90:
                        signal_color = "#ff5555"  # Poor signal - red
                    elif signal_value < -70:
                        signal_color = "#ffff55"  # Medium signal - yellow
                    else:
                        signal_color = "#55ff55"  # Good signal - green

                    signal_text = f"Signal: {signal_value}"
                    draw.text((x + padding, y + y_offset), signal_text, font=self.fonts["medium"],
                              fill=signal_color)
                    y_offset += row_height

        elif sensor_type == "THSensor":
            if sensor.get("temperature", "unknown") != "unknown":
                temp_text = f"Temp: {sensor['temperature']}°{sensor.get('temperatureUnit', 'F')}"
                draw.text((x + padding, y + y_offset), temp_text, font=self.fonts["medium"], fill="#ffffff")
                y_offset += row_height

            if sensor.get("humidity", "unknown") != "unknown":
                humidity_text = f"Humidity: {sensor['humidity']}%"
                draw.text((x + padding, y + y_offset), humidity_text, font=self.fonts["medium"],
                          fill="#ffffff")
                y_offset += row_height

            if "battery" in sensor and sensor["battery"] is not None:
                battery_value = map_battery_value(safe_int(sensor["battery"]))
                if battery_value is not None:
                    # Colorize battery level
                    if battery_value <= 25:
                        batt_color = "#ff5555"  # Critical - red
                    elif battery_value <= 50:
                        batt_color = "#ffff55"  # Low - yellow
                    else:
                        batt_color = "#ffffff"  # Good - white

                    batt_text = f"Battery: {battery_value}%"
                    draw.text((x + padding, y + y_offset), batt_text, font=self.fonts["medium"],
                              fill=batt_color)
                    y_offset += row_height

            if "signal" in sensor:
                signal_value = safe_int(sensor["signal"])
                if signal_value is not None:
                    # Colorize signal strength
                    if signal_value < -90:
                        signal_color = "#ff5555"  # Poor signal - red
                    elif signal_value < -70:
                        signal_color = "#ffff55"  # Medium signal - yellow
                    else:
                        signal_color = "#55ff55"  # Good signal - green

                    signal_text = f"Signal: {signal_value}"
                    draw.text((x + padding, y + y_offset), signal_text, font=self.fonts["medium"],
                              fill=signal_color)
                    y_offset += row_height

        elif sensor_type in ["Outlet", "MultiOutlet"]:
            if "signal" in sensor:
                signal_value = safe_int(sensor["signal"])
                if signal_value is not None:
                    # Colorize signal strength
                    if signal_value < -90:
                        signal_color = "#ff5555"  # Poor signal - red
                    elif signal_value < -70:
                        signal_color = "#ffff55"  # Medium signal - yellow
                    else:
                        signal_color = "#55ff55"  # Good signal - green

                    signal_text = f"Signal: {signal_value}"
                    draw.text((x + padding, y + y_offset), signal_text, font=self.fonts["medium"],
                              fill=signal_color)

    def _render_sensor_panel(self, draw: ImageDraw.ImageDraw, sensor: Dict[str, Any],
                             x: int, y: int) -> None:
        """
        Render a single sensor panel with enhanced visual indicators.

        Args:
            draw: PIL ImageDraw object
            sensor: Sensor data dictionary
            x: X-coordinate of the sensor panel
            y: Y-coordinate of the sensor panel

        Returns:
            None
        """
        panel_width = self.layout_params["panel_width"]
        panel_height = self.layout_params["panel_height"]
        padding = self.layout_params["padding"]
        title_height = self.layout_params["title_height"]

        # Check if this is the newest alarm sensor for highlighting
        is_newest_alarm = sensor.get("deviceId") == self.newest_alarm_id

        # Draw panel background with appropriate coloring
        # Use different colors for newest alarm, other alarms, and normal sensors
        device_id = sensor.get("deviceId", "")
        is_in_alarm = device_id in [s.get("deviceId") for s in self.alarm_sensors]

        if is_newest_alarm:
            # Newest alarm - bright red
            gradient_top = "#ff3333"
            gradient_bottom = "#cc0000"
            outline_color = "#ffff00"  # Yellow outline for newest alarm
            outline_width = 3
        elif is_in_alarm:
            # Other alarms - standard red
            gradient_top = "#cc3333"
            gradient_bottom = "#aa0000"
            outline_color = "#ff5555"
            outline_width = 2
        else:
            # Normal sensor - dark gray
            gradient_top = "#333333"
            gradient_bottom = "#222222"
            outline_color = "#555555"
            outline_width = 1

        # Draw panel outline
        for i in range(outline_width):
            draw.rectangle(
                [(x+i, y+i), (x + panel_width-i, y + panel_height-i)],
                fill=None,
                outline=outline_color
            )

        # Fill panel background
        draw.rectangle(
            [(x+outline_width, y+outline_width),
             (x + panel_width-outline_width, y + panel_height-outline_width)],
            fill=gradient_bottom
        )

        # Draw a gradient header bar
        header_height = title_height + padding
        draw.rectangle([(x, y), (x + panel_width, y + header_height)], fill=gradient_top)

        # Draw sensor name - truncate if needed
        sensor_name = sensor.get("name", "Unknown")
        sensor_name = self._truncate_text(draw, sensor_name, self.fonts["large"], panel_width - (padding * 2))

        # Use larger font and add emphasis indicator for newest alarm
        if is_newest_alarm:
            name_font = self.fonts["xl"]
            # Add "NEW ALARM" indicator
            draw.text((x + padding, y + 2), "⚠ NEW ALARM ⚠", font=self.fonts["medium"], fill="#ffff00")
            draw.text((x + padding, y + title_height), sensor_name, font=name_font, fill="#ffffff")
        else:
            name_font = self.fonts["large"]
            draw.text((x + padding, y + padding), sensor_name, font=name_font, fill="#ffffff")

        sensor_type = sensor.get("type")
        state = sensor.get("state", "N/A")
        y_offset = header_height + padding

        # Handle outlets differently: show status based on power
        if sensor_type in ["Outlet", "MultiOutlet"]:
            if "power" in sensor:
                power = safe_float(sensor["power"])
                if power is not None:
                    status = "On" if power > 0 else "Off"
                    status_color = "#55ff55" if power > 0 else "#ff5555"  # Green for on, red for off
                    status_text = f"Status: {status} ({power}W)"
                    draw.text((x + padding, y + y_offset), status_text, font=self.fonts["medium"],
                              fill=status_color)
                else:
                    draw.text((x + padding, y + y_offset), "Status: Unknown", font=self.fonts["medium"], fill="#aaaaaa")
                y_offset += self.layout_params["sensor_row_height"]
            elif "powers" in sensor and isinstance(sensor["powers"], list):
                powers = sensor["powers"]
                for j, power in enumerate(powers[:2]):
                    power_val = safe_float(power)
                    if power_val is not None:
                        status = "On" if power_val > 0 else "Off"
                        status_color = "#55ff55" if power_val > 0 else "#ff5555"  # Green for on, red for off
                        outlet_text = f"Outlet {j + 1}: {status} ({power_val}W)"
                        draw.text((x + padding, y + y_offset + j * self.layout_params["sensor_row_height"]),
                                 outlet_text, font=self.fonts["medium"], fill=status_color)
                    else:
                        draw.text((x + padding, y + y_offset + j * self.layout_params["sensor_row_height"]),
                                 f"Outlet {j + 1}: Unknown", font=self.fonts["medium"], fill="#aaaaaa")
                y_offset += len(powers[:2]) * self.layout_params["sensor_row_height"]
            else:
                draw.text((x + padding, y + y_offset), "Status: Unknown", font=self.fonts["medium"], fill="#aaaaaa")
                y_offset += self.layout_params["sensor_row_height"]
        else:
            # For non-outlet sensors, display the state with appropriate coloring
            if sensor_type == "THSensor" and isinstance(state, dict):
                state_text = format_smoke_state(state)
                if state_text == "normal":
                    state_color = "#55ff55"  # Green for normal
                else:
                    state_color = "#ff5555"  # Red for alarms
            elif isinstance(state, str) and state.lower() in ["open", "motion"]:
                state_text = state.upper()  # Make alarmed states more visible
                state_color = "#ff5555"  # Red for open/motion
                # Use the largest font for alarm states
                draw.text((x + padding, y + y_offset), f"State: {state_text}", font=self.fonts["xl"], fill=state_color)
                y_offset += self.layout_params["sensor_row_height"] * 1.5
            elif isinstance(state, str) and state.lower() in ["closed", "no motion"]:
                state_text = state
                state_color = "#55ff55"  # Green for closed/no motion
                draw.text((x + padding, y + y_offset), f"State: {state_text}", font=self.fonts["medium"], fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]
            else:
                state_text = str(state)
                state_color = "#ffffff"  # White for other states
                draw.text((x + padding, y + y_offset), f"State: {state_text}", font=self.fonts["medium"], fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]

        # Render additional sensor details
        self._render_sensor_details(draw, sensor, x, y, panel_width, y_offset)

    def _render_normal_view(self, draw: ImageDraw.ImageDraw) -> None:
        """
        Render the normal view of the dashboard with updated time indicator.

        Args:
            draw: PIL ImageDraw object

        Returns:
            None
        """
        width, height = self.current_width, self.current_height
        banner_height = self.layout_params["banner_height"]
        padding = self.layout_params["padding"]

        # Draw gray banner at the top
        draw.rectangle([(0, 0), (width, banner_height)], fill="#333333")
        draw.text((padding, padding), "SENSORS", font=self.fonts["xl"], fill="#ffffff")

        # Add update time indicator in the middle of the banner
        update_text = self._format_time_since_update()
        update_text_width = self._get_text_width(draw, update_text, self.fonts["large"])
        update_x = (width - update_text_width) // 2
        draw.text((update_x, padding), update_text, font=self.fonts["large"], fill="#FFFF99")  # Yellow-ish for visibility

        # Calculate and display summary on the banner
        active_count = len(self.sensor_data)
        alarm_count = len(self.alarm_sensors)
        summary_text = f"Active: {active_count} | Alarms: {alarm_count}"
        text_width = self._get_text_width(draw, summary_text, self.fonts["large"])
        draw.text((width - text_width - padding, padding), summary_text, font=self.fonts["large"], fill="#ffffff")

        # Handle case with no sensor data
        if not self.sensor_data:
            draw.text((padding, banner_height + padding), "No sensor data available", font=self.fonts["large"], fill="#ffffff")
            return

        # Add pagination indicator
        if self.total_pages > 1:
            page_text = f"Page {self.current_page + 1}/{self.total_pages}"
            page_x = (width - self._get_text_width(draw, page_text, self.fonts["medium"])) // 2
            draw.text((page_x, banner_height - padding - self.fonts["medium"].size), page_text, font=self.fonts["medium"], fill="#ffffff")

        # Pagination logic
        start_idx = self.current_page * self.sensors_per_page
        end_idx = min(start_idx + self.sensors_per_page, len(self.sensor_data))
        sensors_to_show = self.sensor_data[start_idx:end_idx]

        # Render each sensor in a grid
        grid_cols = self.layout_params["grid_cols"]
        panel_width = self.layout_params["panel_width"]
        panel_height = self.layout_params["panel_height"]

        for i, sensor in enumerate(sensors_to_show):
            row = i // grid_cols
            col = i % grid_cols

            # Calculate position with padding
            x = padding + col * (panel_width + padding)
            y = banner_height + padding + row * (panel_height + padding)

            self._render_sensor_panel(draw, sensor, x, y)

    def _render_alarm_view(self, draw: ImageDraw.ImageDraw) -> None:
        """
        Render the alarm view of the dashboard with updated time indicator.

        Args:
            draw: PIL ImageDraw object

        Returns:
            None
        """
        width, height = self.current_width, self.current_height
        banner_height = self.layout_params["banner_height"]
        padding = self.layout_params["padding"]

        # Draw bright red banner at the top (brighter than before)
        draw.rectangle([(0, 0), (width, banner_height)], fill="#ff0000")
        draw.text((padding, padding), "⚠ SENSORS IN ALARM ⚠", font=self.fonts["xl"], fill="#ffffff")

        # Add update time indicator in the middle of the banner
        update_text = self._format_time_since_update()
        update_text_width = self._get_text_width(draw, update_text, self.fonts["large"])
        update_x = (width - update_text_width) // 2
        draw.text((update_x, padding), update_text, font=self.fonts["large"], fill="#ffffff")

        # Calculate and display summary on the banner
        active_count = len(self.sensor_data)
        alarm_count = len(self.alarm_sensors)
        summary_text = f"Active: {active_count} | Alarms: {alarm_count}"
        text_width = self._get_text_width(draw, summary_text, self.fonts["large"])
        draw.text((width - text_width - padding, padding), summary_text, font=self.fonts["large"], fill="#ffffff")

        # Handle case with no alarm sensors
        if not self.alarm_sensors:
            draw.text((padding, banner_height + padding), "No sensors in alarm", font=self.fonts["large"], fill="#ffffff")
            return

        # Determine how many alarms to show based on available space
        grid_cols = self.layout_params["grid_cols"]
        panel_width = self.layout_params["panel_width"]
        panel_height = self.layout_params["panel_height"]

        # Calculate max sensors that fit in the available space
        max_rows = (height - banner_height - padding) // (panel_height + padding)
        max_sensors = max_rows * grid_cols

        # Reorder alarms to put newest alarm first if it exists
        if self.newest_alarm_id:
            ordered_alarms = []
            # Add newest alarm first
            for sensor in self.alarm_sensors:
                if sensor.get("deviceId") == self.newest_alarm_id:
                    ordered_alarms.append(sensor)
                    break

            # Add all other alarms
            for sensor in self.alarm_sensors:
                if sensor.get("deviceId") != self.newest_alarm_id:
                    ordered_alarms.append(sensor)

            sensors_to_show = ordered_alarms[:max_sensors]
        else:
            # Just show alarms in original order
            sensors_to_show = self.alarm_sensors[:max_sensors]

        # If we have more alarms than can fit on screen, add a note
        if len(self.alarm_sensors) > max_sensors:
            more_text = f"+{len(self.alarm_sensors) - max_sensors} more alarms"
            more_width = self._get_text_width(draw, more_text, self.fonts["medium"])
            more_x = (width - more_width) // 2
            draw.text((more_x, banner_height - padding - self.fonts["medium"].size),
                     more_text, font=self.fonts["medium"], fill="#ffff00")

        for i, sensor in enumerate(sensors_to_show):
            row = i // grid_cols
            col = i % grid_cols

            # Calculate position with padding
            x = padding + col * (panel_width + padding)
            y = banner_height + padding + row * (panel_height + padding)

            self._render_sensor_panel(draw, sensor, x, y)