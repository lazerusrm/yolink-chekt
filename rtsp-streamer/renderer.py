"""
Enhanced Dashboard UI rendering for the YoLink Dashboard RTSP Server.
Supports multiple resolutions with appropriate layouts, alarm highlighting,
and update time indicators for improved readability.

This renderer implementation has been optimized for performance and memory usage:
1. Caches fonts and layouts based on resolution to avoid repeated loading
2. Implements frame caching to reduce CPU usage
3. Uses thread-safe operations to prevent race conditions
4. Optimizes text rendering and measurement operations
5. Minimizes object creation during rendering loops
"""
import time
import logging
import threading
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
    Optimized for performance and memory efficiency.
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
        self.newest_alarm_id = None  # Track the newest alarm for highlighting

        # Initialize default resolution values
        self.current_width = config.get("width", 1920)
        self.current_height = config.get("height", 1080)
        self.sensors_per_page = config.get("sensors_per_page", 20)

        # Initialize frame caching
        self.last_frame = None
        self.last_render_time = 0
        self.last_render_config = {}

        # Thread safety
        self.render_lock = threading.RLock()

        # Cache for layout parameters and fonts based on resolution
        self.cached_fonts_resolution = None
        self.cached_layout_resolution = None
        self.layout_params = None
        self.fonts = None

        # Reusable objects for rendering
        self.buffer = None

        # Initialize layout and fonts for the current resolution
        self._calc_layout_params()
        self._load_fonts_for_resolution()

    def _load_fonts_for_resolution(self) -> Dict[str, ImageFont.FreeTypeFont]:
        """
        Load appropriate fonts based on the current resolution.
        Cached to avoid repeatedly loading the same fonts.

        Returns:
            Dict[str, ImageFont.FreeTypeFont]: Dictionary of font objects
        """
        # Check if we already have fonts loaded for this resolution
        if (self.cached_fonts_resolution == (self.current_width, self.current_height) and
            self.fonts is not None):
            return self.fonts

        # Calculate font sizes based on screen resolution
        base_font_size = max(18, int(self.current_height / 36))
        title_font_size = max(28, int(self.current_height / 20))
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

        # Update cache
        self.cached_fonts_resolution = (self.current_width, self.current_height)
        self.fonts = fonts

        return self.fonts

    def _calc_layout_params(self) -> Dict[str, Any]:
        """
        Calculate layout parameters based on current resolution.
        Cached to avoid recalculating the same parameters repeatedly.

        Returns:
            Dict[str, Any]: Layout parameters
        """
        # Check if we already have layout parameters for this resolution
        if (self.cached_layout_resolution == (self.current_width, self.current_height, self.sensors_per_page) and
            self.layout_params is not None):
            return self.layout_params

        # Base everything on relative proportions of the screen
        width, height = self.current_width, self.current_height

        # Banner height calculation
        banner_height = max(60, min(80, height // 12))

        # Calculate the grid size based on sensors_per_page
        grid_cols = min(5, max(1, int(self.sensors_per_page ** 0.5)))
        grid_rows = (self.sensors_per_page + grid_cols - 1) // grid_cols

        # Panel size calculation
        padding = max(8, min(20, height // 72))
        panel_width = max(280, (width - (grid_cols + 1) * padding) // grid_cols)
        panel_height = max(180, (height - banner_height - (grid_rows + 1) * padding) // grid_rows)

        # Create layout parameters dictionary
        layout_params = {
            "grid_cols": grid_cols,
            "grid_rows": grid_rows,
            "panel_width": panel_width,
            "panel_height": panel_height,
            "banner_height": banner_height,
            "padding": padding,
            "title_height": max(30, min(40, height // 27)),
            "sensor_row_height": max(24, min(32, height // 34)),
        }

        # Update cache
        self.cached_layout_resolution = (self.current_width, self.current_height, self.sensors_per_page)
        self.layout_params = layout_params

        return self.layout_params

    def set_resolution(self, width: int, height: int, sensors_per_page: Optional[int] = None) -> None:
        """
        Update the renderer's resolution and adjust layout accordingly.
        Optimized to skip unnecessary recalculations.

        Args:
            width: New width in pixels
            height: New height in pixels
            sensors_per_page: Optional number of sensors to show per page
        """
        with self.render_lock:
            # Check if there's no change in configuration
            if (width == self.current_width and height == self.current_height and
                    (sensors_per_page is None or sensors_per_page == self.sensors_per_page)):
                return

            # Update dimensions
            self.current_width = width
            self.current_height = height

            # Update sensors per page if specified
            if sensors_per_page is not None:
                self.sensors_per_page = sensors_per_page
            elif width != self.current_width or height != self.current_height:
                # Adjust sensors per page based on resolution if not explicitly specified
                if width >= 1920 and height >= 1080:
                    self.sensors_per_page = 20  # Full HD
                elif width >= 1280 and height >= 720:
                    self.sensors_per_page = 12  # HD
                elif width >= 960 and height >= 540:
                    self.sensors_per_page = 6  # qHD
                else:
                    self.sensors_per_page = 4  # Low resolution

            # Update layout and fonts
            self._calc_layout_params()
            self._load_fonts_for_resolution()
            self._update_pagination()

            # Invalidate frame cache since resolution changed
            self.last_frame = None

            logger.info(f"Renderer resolution set to {width}x{height} with {self.sensors_per_page} sensors per page")

    def _update_pagination(self) -> None:
        """
        Update pagination based on current sensors_per_page.
        """
        with self.render_lock:
            total_sensors = len(self.sensor_data)
            new_total_pages = max(1, (total_sensors + self.sensors_per_page - 1) // self.sensors_per_page)

            # Only update if the number of pages has changed
            if new_total_pages != self.total_pages:
                self.total_pages = new_total_pages

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
        with self.render_lock:
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

            # Process each sensor
            for s in sensors:
                if not s:
                    continue

                # Process last_seen date
                last_seen = s.get("last_seen")
                if last_seen == "never":
                    continue

                try:
                    last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                    if last_seen_date < cutoff_date:
                        continue
                except (ValueError, TypeError):
                    continue

                # Sensor is valid, add to data
                self.sensor_data.append(s)

                # Extract key fields
                sensor_type = s.get("type")
                state = s.get("state")
                signal = safe_int(s.get("signal"))
                battery = safe_int(s.get("battery"))
                device_id = s.get("deviceId", "UnknownID")

                # Normalize state
                state_str = str(state).strip().lower() if state is not None and not isinstance(state, dict) else ""

                # Map battery value if present
                mapped_battery = map_battery_value(battery) if battery is not None else None

                # Determine alarm state
                is_alarm = False
                alarm_reason = []

                # Process by sensor type
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
                            alarm_reason.append(f"Alarm state active")
                    if mapped_battery is not None and mapped_battery <= 25:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 25%")
                    if signal is not None and signal < -119:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -119")

                # Add to alarm list if applicable
                if is_alarm:
                    self.alarm_sensors.append(s)

            # Get current alarm IDs
            current_alarm_ids = set(s.get("deviceId") for s in self.alarm_sensors if s.get("deviceId"))

            # Detect new alarms
            new_alarm_ids = current_alarm_ids - previous_alarm_ids

            # Process new alarms
            if new_alarm_ids:
                self.new_alarm_triggered = True
                self.alarm_display_timer = time.time()
                self.newest_alarm_id = next(iter(new_alarm_ids))  # Use first new alarm ID

                # Log newest alarm name
                for s in self.alarm_sensors:
                    if s.get("deviceId") == self.newest_alarm_id:
                        logger.info(f"New alarm highlighted: {s.get('name', 'Unknown')} (ID: {self.newest_alarm_id})")
                        break

            # Update pagination based on the new data
            self._update_pagination()

            # Invalidate frame cache since data changed
            self.last_frame = None

            logger.info(
                f"Updated: {len(self.sensor_data)} sensors, {len(self.alarm_sensors)} alarms, {self.total_pages} pages")

    def set_page(self, page_num: int) -> None:
        """
        Set the current page number for pagination.

        Args:
            page_num: Page number (0-based)
        """
        with self.render_lock:
            if 0 <= page_num < self.total_pages:
                if page_num != self.current_page:
                    self.current_page = page_num
                    # Invalidate frame cache since page changed
                    self.last_frame = None
                    logger.info(f"Set page to {page_num + 1}/{self.total_pages}")
            else:
                logger.warning(f"Attempted to set invalid page {page_num + 1}, valid range: 1-{self.total_pages}")

    def should_update_frame(self) -> bool:
        """
        Determine if a new frame needs to be rendered based on data changes and timing.
        This helps reduce CPU usage by avoiding unnecessary renders.

        Returns:
            bool: True if frame should be updated, False otherwise
        """
        current_time = time.time()

        # Always render if it's the first time or frame was invalidated
        if self.last_frame is None:
            return True

        # High priority updates - check for alarm state changes
        if self.new_alarm_triggered:
            return True

        # Check for transitions between display states
        if self.alarm_display_timer > 0:
            time_in_current_state = current_time - self.alarm_display_timer
            # Transition from alarm to normal view
            if (time_in_current_state >= self.alarm_display_duration and
                    time_in_current_state < self.alarm_display_duration + 0.5):
                return True
            # Transition from normal to default view
            if (time_in_current_state >= self.alarm_display_duration + self.normal_display_duration and
                    time_in_current_state < self.alarm_display_duration + self.normal_display_duration + 0.5):
                return True

        # Enforce minimum interval between renders
        min_interval = 1.0 / max(1, self.config.get("frame_rate", 6))
        if current_time - self.last_render_time < min_interval:
            return False

        return True

    def render_frame(self, width: int, height: int) -> Image.Image:
        """
        Render a frame of the dashboard.
        Optimized with frame caching to reduce CPU usage.

        Args:
            width: Frame width in pixels
            height: Frame height in pixels

        Returns:
            PIL.Image: Rendered frame
        """
        with self.render_lock:
            # Update resolution if different from current
            if width != self.current_width or height != self.current_height:
                self.set_resolution(width, height)

            # Check if we need to update the frame
            if not self.should_update_frame():
                return self.last_frame

            # Create new image
            current_time = time.time()
            image = Image.new("RGB", (width, height), "#000000")
            draw = ImageDraw.Draw(image)

            # Determine which view to render
            if self.alarm_sensors and (current_time - self.alarm_display_timer < self.alarm_display_duration):
                self._render_alarm_view(draw)
            elif current_time - self.alarm_display_timer < self.alarm_display_duration + self.normal_display_duration:
                self._render_normal_view(draw)
            else:
                self.alarm_display_timer = 0
                self.new_alarm_triggered = False
                self.newest_alarm_id = None
                self._render_normal_view(draw)

            # Update render time and cache the frame
            self.last_render_time = current_time
            self.last_frame = image

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
        Uses a more efficient approach than the original method.

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

        # Check if text already fits
        if self._get_text_width(draw, text, font) <= max_width:
            return text

        ellipsis = "..."
        ellipsis_width = self._get_text_width(draw, ellipsis, font)

        # If even the ellipsis is too wide, return empty string
        if ellipsis_width >= max_width:
            return ""

        # Binary search for the maximum length that fits
        available_width = max_width - ellipsis_width
        start, end = 0, len(text)

        while start < end:
            mid = (start + end + 1) // 2
            if self._get_text_width(draw, text[:mid], font) <= available_width:
                start = mid
            else:
                end = mid - 1

        return text[:start] + ellipsis

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
        """
        padding = self.layout_params["padding"]
        row_height = self.layout_params["sensor_row_height"]
        sensor_type = sensor.get("type")

        # Process sensor details based on type
        if sensor_type in ["MotionSensor", "ContactSensor", "DoorSensor"]:
            # Battery information
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

            # Signal information
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
            # Temperature information
            if sensor.get("temperature", "unknown") != "unknown":
                temp_text = f"Temp: {sensor['temperature']}°{sensor.get('temperatureUnit', 'F')}"
                draw.text((x + padding, y + y_offset), temp_text, font=self.fonts["medium"], fill="#ffffff")
                y_offset += row_height

            # Humidity information
            if sensor.get("humidity", "unknown") != "unknown":
                humidity_text = f"Humidity: {sensor['humidity']}%"
                draw.text((x + padding, y + y_offset), humidity_text, font=self.fonts["medium"],
                         fill="#ffffff")
                y_offset += row_height

            # Battery information
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

            # Signal information
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
            # Signal information only for outlets
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
        """
        panel_width = self.layout_params["panel_width"]
        panel_height = self.layout_params["panel_height"]
        padding = self.layout_params["padding"]
        title_height = self.layout_params["title_height"]

        # Check if this is the newest alarm sensor for highlighting
        device_id = sensor.get("deviceId", "")
        is_newest_alarm = device_id == self.newest_alarm_id
        is_in_alarm = device_id in [s.get("deviceId") for s in self.alarm_sensors]

        # Determine panel styling based on alarm state
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

        # Draw panel outline efficiently
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

        # Draw header bar
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

        # Get sensor type and state
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
                for j, power in enumerate(powers[:2]):  # Only show first 2 outlets to save space
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
                draw.text((x + padding, y + y_offset), f"State: {state_text}",
                         font=self.fonts["medium"], fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]
            elif isinstance(state, str) and state.lower() in ["open", "motion"]:
                state_text = state.upper()  # Make alarmed states more visible
                state_color = "#ff5555"  # Red for open/motion
                # Use the largest font for alarm states
                draw.text((x + padding, y + y_offset), f"State: {state_text}",
                         font=self.fonts["xl"], fill=state_color)
                y_offset += self.layout_params["sensor_row_height"] * 1.5
            elif isinstance(state, str) and state.lower() in ["closed", "no motion"]:
                state_text = state
                state_color = "#55ff55"  # Green for closed/no motion
                draw.text((x + padding, y + y_offset), f"State: {state_text}",
                         font=self.fonts["medium"], fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]
            else:
                state_text = str(state)
                state_color = "#ffffff"  # White for other states
                draw.text((x + padding, y + y_offset), f"State: {state_text}",
                         font=self.fonts["medium"], fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]

        # Render additional sensor details
        self._render_sensor_details(draw, sensor, x, y, panel_width, y_offset)