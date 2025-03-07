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
        self.newest_alarm_id = None

        # Initialize default resolution values with type safety
        self.current_width = safe_int(config.get("width", 1920))
        self.current_height = safe_int(config.get("height", 1080))
        self.sensors_per_page = safe_int(config.get("sensors_per_page", 20))

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
        Improved scaling for different resolutions.

        Returns:
            Dict[str, ImageFont.FreeTypeFont]: Dictionary of font objects
        """
        if (self.cached_fonts_resolution == (self.current_width, self.current_height, self.sensors_per_page) and
                self.fonts is not None):
            return self.fonts

        # Calculate panel dimensions to better adjust font sizes
        layout = self._calc_layout_params()
        panel_width = layout["panel_width"]
        panel_height = layout["panel_height"]

        # Dynamic sizing based on panel dimensions rather than just screen height
        # More aggressive scaling for lower resolutions
        if self.current_width <= 640:  # Mobile profile
            base_font_size = max(10, int(panel_height / 12))
            title_font_size = max(14, int(panel_height / 8))
            xl_font_size = max(16, int(panel_height / 6))
        elif self.current_width <= 960:  # Low-res profile
            base_font_size = max(12, int(panel_height / 10))
            title_font_size = max(18, int(panel_height / 7))
            xl_font_size = max(24, int(panel_height / 5))
        else:  # Main profile
            base_font_size = max(14, int(panel_height / 9))
            title_font_size = max(20, int(panel_height / 6))
            xl_font_size = max(28, int(panel_height / 4))

        try:
            fonts = {
                "xl": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", xl_font_size),
                "large": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", title_font_size),
                "medium": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                                             base_font_size + 2),
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

        logger.info(
            f"Loaded fonts for {self.current_width}x{self.current_height} - XL: {xl_font_size}px, Large: {title_font_size}px, Medium: {base_font_size + 2}px, Small: {base_font_size}px")

        self.cached_fonts_resolution = (self.current_width, self.current_height, self.sensors_per_page)
        self.fonts = fonts
        return self.fonts

    def _calc_layout_params(self) -> Dict[str, Any]:
        """
        Calculate layout parameters based on current resolution.
        Improved to better handle different resolutions and sensor counts.
        Cached to avoid recalculating the same parameters repeatedly.

        Returns:
            Dict[str, Any]: Layout parameters
        """
        if (self.cached_layout_resolution == (self.current_width, self.current_height, self.sensors_per_page) and
                self.layout_params is not None):
            return self.layout_params

        width, height = self.current_width, self.current_height
        sensors_per_page = max(1, self.sensors_per_page)  # Ensure positive integer

        # More responsive banner height based on resolution
        if height <= 360:
            banner_height = max(30, min(40, height // 8))
        elif height <= 720:
            banner_height = max(40, min(60, height // 10))
        else:
            banner_height = max(60, min(80, height // 12))

        # Adjust grid layout based on sensors_per_page
        # Use fewer columns for small screens to allow bigger panels
        if width <= 640:
            max_cols = 2
        elif width <= 960:
            max_cols = 3
        else:
            max_cols = 5

        grid_cols = min(max_cols, max(1, min(sensors_per_page, int(sensors_per_page ** 0.5))))
        grid_rows = (sensors_per_page + grid_cols - 1) // grid_cols

        # Scale padding based on resolution
        padding = max(4, min(16, height // 80))

        # Calculate panel dimensions based on available space
        panel_width = max(180, (width - (grid_cols + 1) * padding) // grid_cols)
        panel_height = max(120, (height - banner_height - (grid_rows + 1) * padding) // grid_rows)

        # Scale internal element heights based on panel size
        title_height = max(20, min(36, panel_height // 6))
        sensor_row_height = max(16, min(28, (panel_height - title_height) // 5))

        layout_params = {
            "grid_cols": grid_cols,
            "grid_rows": grid_rows,
            "panel_width": panel_width,
            "panel_height": panel_height,
            "banner_height": banner_height,
            "padding": padding,
            "title_height": title_height,
            "sensor_row_height": sensor_row_height,
        }

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
            width = safe_int(width)
            height = safe_int(height)
            sensors_per_page = safe_int(sensors_per_page) if sensors_per_page is not None else None

            if (width == self.current_width and height == self.current_height and
                    (sensors_per_page is None or sensors_per_page == self.sensors_per_page)):
                return

            self.current_width = width
            self.current_height = height

            if sensors_per_page is not None:
                self.sensors_per_page = sensors_per_page
            elif width != self.current_width or height != self.current_height:
                if width >= 1920 and height >= 1080:
                    self.sensors_per_page = 20
                elif width >= 1280 and height >= 720:
                    self.sensors_per_page = 12
                elif width >= 960 and height >= 540:
                    self.sensors_per_page = 6
                else:
                    self.sensors_per_page = 4

            self._calc_layout_params()
            self._load_fonts_for_resolution()
            self._update_pagination()

            self.last_frame = None
            logger.info(f"Renderer resolution set to {width}x{height} with {self.sensors_per_page} sensors per page")

    def _update_pagination(self) -> None:
        """
        Update pagination based on current sensors_per_page.
        """
        with self.render_lock:
            total_sensors = len(self.sensor_data)
            new_total_pages = max(1, (total_sensors + self.sensors_per_page - 1) // self.sensors_per_page)

            if new_total_pages != self.total_pages:
                self.total_pages = new_total_pages
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

            previous_alarm_ids = set(s.get("deviceId") for s in self.alarm_sensors if s.get("deviceId"))
            self.sensor_data = []
            self.alarm_sensors = []
            self.last_update_time = time.time()
            logger.info(f"Received {len(sensors)} sensors via WebSocket")

            cutoff_date = datetime.now() - timedelta(days=60)

            for s in sensors:
                if not s:
                    continue

                last_seen = s.get("last_seen")
                if last_seen == "never":
                    continue

                try:
                    last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                    if last_seen_date < cutoff_date:
                        continue
                except (ValueError, TypeError):
                    continue

                self.sensor_data.append(s)
                sensor_type = s.get("type")
                state = s.get("state")
                signal = safe_int(s.get("signal"))
                battery = safe_int(s.get("battery"))
                device_id = s.get("deviceId", "UnknownID")

                state_str = str(state).strip().lower() if state is not None and not isinstance(state, dict) else ""
                mapped_battery = map_battery_value(battery) if battery is not None else None

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
                            alarm_reason.append(f"Alarm state active")
                    if mapped_battery is not None and mapped_battery <= 25:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 25%")
                    if signal is not None and signal < -119:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -119")

                if is_alarm:
                    self.alarm_sensors.append(s)

            current_alarm_ids = set(s.get("deviceId") for s in self.alarm_sensors if s.get("deviceId"))
            new_alarm_ids = current_alarm_ids - previous_alarm_ids

            if new_alarm_ids:
                self.new_alarm_triggered = True
                self.alarm_display_timer = time.time()
                self.newest_alarm_id = next(iter(new_alarm_ids))
                for s in self.alarm_sensors:
                    if s.get("deviceId") == self.newest_alarm_id:
                        logger.info(f"New alarm highlighted: {s.get('name', 'Unknown')} (ID: {self.newest_alarm_id})")
                        break

            self._update_pagination()
            self.last_frame = None
            logger.info(f"Updated: {len(self.sensor_data)} sensors, {len(self.alarm_sensors)} alarms, {self.total_pages} pages")

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

        if self.last_frame is None:
            return True

        if self.new_alarm_triggered:
            return True

        if self.alarm_display_timer > 0:
            time_in_current_state = current_time - self.alarm_display_timer
            if (time_in_current_state >= self.alarm_display_duration and
                    time_in_current_state < self.alarm_display_duration + 0.5):
                return True
            if (time_in_current_state >= self.alarm_display_duration + self.normal_display_duration and
                    time_in_current_state < self.alarm_display_duration + self.normal_display_duration + 0.5):
                return True

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
            if width != self.current_width or height != self.current_height:
                self.set_resolution(width, height)

            if not self.should_update_frame():
                return self.last_frame

            current_time = time.time()
            image = Image.new("RGB", (width, height), "#000000")
            draw = ImageDraw.Draw(image)

            if self.alarm_sensors and (current_time - self.alarm_display_timer < self.alarm_display_duration):
                self._render_alarm_view(draw)
            elif current_time - self.alarm_display_timer < self.alarm_display_duration + self.normal_display_duration:
                self._render_normal_view(draw)
            else:
                self.alarm_display_timer = 0
                self.new_alarm_triggered = False
                self.newest_alarm_id = None
                self._render_normal_view(draw)

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
        More aggressive truncation for smaller widths.
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

        if self._get_text_width(draw, text, font) <= max_width:
            return text

        # For very small widths, be more aggressive with shorter ellipsis
        if max_width < 80:
            ellipsis = ".."
        else:
            ellipsis = "..."

        ellipsis_width = self._get_text_width(draw, ellipsis, font)

        if ellipsis_width >= max_width:
            return ""

        available_width = max_width - ellipsis_width

        # Faster binary search for the right cutoff point
        start, end = 0, len(text)

        while start < end:
            mid = (start + end + 1) // 2
            if self._get_text_width(draw, text[:mid], font) <= available_width:
                start = mid
            else:
                end = mid - 1

        return text[:start] + ellipsis

    def _render_sensor_details(self, draw: ImageDraw.ImageDraw, sensor: Dict[str, Any],
                               x: int, y: int, panel_width: int, y_offset: int = 50,
                               is_small_panel: bool = False) -> None:
        """
        Render sensor details in a sensor panel with improved handling for small panels.

        Args:
            draw: PIL ImageDraw object
            sensor: Sensor data dictionary
            x: X-coordinate of the sensor panel
            y: Y-coordinate of the sensor panel
            panel_width: Width of the panel in pixels
            y_offset: Starting Y-offset for additional details
            is_small_panel: Flag indicating if we're rendering in a small panel
        """
        padding = self.layout_params["padding"]
        row_height = self.layout_params["sensor_row_height"]
        sensor_type = sensor.get("type")

        # Use smaller font for details in small panels
        detail_font = self.fonts["small"] if not is_small_panel else self.fonts["small"]

        # Calculate available height for details
        max_y = y + self.layout_params["panel_height"] - padding

        # For small panels, show condensed info
        if sensor_type in ["MotionSensor", "ContactSensor", "DoorSensor"]:
            if "battery" in sensor and sensor["battery"] is not None and y_offset < max_y:
                battery_value = map_battery_value(safe_int(sensor["battery"]))
                if battery_value is not None:
                    batt_color = "#ff5555" if battery_value <= 25 else "#ffff55" if battery_value <= 50 else "#ffffff"
                    batt_text = f"Batt: {battery_value}%" if is_small_panel else f"Battery: {battery_value}%"
                    draw.text((x + padding, y + y_offset), batt_text, font=detail_font, fill=batt_color)
                    y_offset += row_height

            if "signal" in sensor and y_offset < max_y:
                signal_value = safe_int(sensor["signal"])
                if signal_value is not None:
                    signal_color = "#ff5555" if signal_value < -90 else "#ffff55" if signal_value < -70 else "#55ff55"
                    signal_text = f"Sig: {signal_value}" if is_small_panel else f"Signal: {signal_value}"
                    draw.text((x + padding, y + y_offset), signal_text, font=detail_font, fill=signal_color)
                    y_offset += row_height

        elif sensor_type == "THSensor":
            if sensor.get("temperature", "unknown") != "unknown" and y_offset < max_y:
                # Cleaner temperature display for small panels
                if is_small_panel:
                    temp_text = f"{sensor['temperature']}°{sensor.get('temperatureUnit', 'F')}"
                else:
                    temp_text = f"Temp: {sensor['temperature']}°{sensor.get('temperatureUnit', 'F')}"
                draw.text((x + padding, y + y_offset), temp_text, font=detail_font, fill="#ffffff")
                y_offset += row_height

            if sensor.get("humidity", "unknown") != "unknown" and y_offset < max_y:
                humidity_text = f"Hum: {sensor['humidity']}%" if is_small_panel else f"Humidity: {sensor['humidity']}%"
                draw.text((x + padding, y + y_offset), humidity_text, font=detail_font, fill="#ffffff")
                y_offset += row_height

            if "battery" in sensor and sensor["battery"] is not None and y_offset < max_y:
                battery_value = map_battery_value(safe_int(sensor["battery"]))
                if battery_value is not None:
                    batt_color = "#ff5555" if battery_value <= 25 else "#ffff55" if battery_value <= 50 else "#ffffff"
                    batt_text = f"Batt: {battery_value}%" if is_small_panel else f"Battery: {battery_value}%"
                    draw.text((x + padding, y + y_offset), batt_text, font=detail_font, fill=batt_color)
                    y_offset += row_height

            if "signal" in sensor and y_offset < max_y:
                signal_value = safe_int(sensor["signal"])
                if signal_value is not None:
                    signal_color = "#ff5555" if signal_value < -90 else "#ffff55" if signal_value < -70 else "#55ff55"
                    signal_text = f"Sig: {signal_value}" if is_small_panel else f"Signal: {signal_value}"
                    draw.text((x + padding, y + y_offset), signal_text, font=detail_font, fill=signal_color)
                    y_offset += row_height

        elif sensor_type in ["Outlet", "MultiOutlet"]:
            if "signal" in sensor and y_offset < max_y:
                signal_value = safe_int(sensor["signal"])
                if signal_value is not None:
                    signal_color = "#ff5555" if signal_value < -90 else "#ffff55" if signal_value < -70 else "#55ff55"
                    signal_text = f"Sig: {signal_value}" if is_small_panel else f"Signal: {signal_value}"
                    draw.text((x + padding, y + y_offset), signal_text, font=detail_font, fill=signal_color)

    def _render_sensor_panel(self, draw: ImageDraw.ImageDraw, sensor: Dict[str, Any],
                             x: int, y: int) -> None:
        """
        Render a single sensor panel with enhanced visual indicators.
        Modernized design with improved alarm visibility.

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

        # Determine if we're in a small resolution mode
        is_small_panel = panel_width < 200 or panel_height < 150

        device_id = sensor.get("deviceId", "")
        is_newest_alarm = device_id == self.newest_alarm_id
        is_in_alarm = device_id in [s.get("deviceId") for s in self.alarm_sensors]

        # Modern color palette
        if is_newest_alarm:
            # More vibrant, attention-grabbing colors for new alarms
            gradient_top = "#FF5252"  # Brighter red
            gradient_bottom = "#D32F2F"  # Deeper red for gradient effect
            outline_color = "#FFD600"  # More saturated yellow
            outline_width = 3 if is_small_panel else 4  # Thicker outline for better visibility
        elif is_in_alarm:
            gradient_top = "#F44336"  # Material Design red
            gradient_bottom = "#C62828"  # Darker red for gradient
            outline_color = "#FF8A80"  # Light red outline
            outline_width = 2 if is_small_panel else 3
        else:
            # More modern dark theme with blue tint for normal panels
            gradient_top = "#37474F"  # Dark blue-grey
            gradient_bottom = "#263238"  # Darker blue-grey
            outline_color = "#546E7A"  # Medium blue-grey
            outline_width = 1

        # Draw panel background with rounded corners effect
        # First fill the entire panel
        draw.rectangle(
            [(x, y), (x + panel_width, y + panel_height)],
            fill=gradient_bottom
        )

        # Draw header with gradient effect - top 20% of panel
        header_height = title_height + padding
        draw.rectangle([(x, y), (x + panel_width, y + header_height)], fill=gradient_top)

        # Draw outline - improved to ensure it surrounds the box properly
        # Draw each side separately for better control
        for i in range(outline_width):
            # Top
            draw.line([(x + i, y + i), (x + panel_width - i, y + i)], fill=outline_color, width=1)
            # Right
            draw.line([(x + panel_width - i, y + i), (x + panel_width - i, y + panel_height - i)], fill=outline_color,
                      width=1)
            # Bottom
            draw.line([(x + panel_width - i, y + panel_height - i), (x + i, y + panel_height - i)], fill=outline_color,
                      width=1)
            # Left
            draw.line([(x + i, y + panel_height - i), (x + i, y + i)], fill=outline_color, width=1)

        # Get sensor name and truncate as needed
        sensor_name = sensor.get("name", "Unknown")
        sensor_name = self._truncate_text(draw, sensor_name,
                                          self.fonts["large" if not is_small_panel else "medium"],
                                          panel_width - (padding * 2))

        # Render sensor name with improved positioning
        name_font = self.fonts["large" if not is_small_panel else "medium"]
        draw.text((x + padding, y + padding), sensor_name, font=name_font, fill="#FFFFFF")

        # Get sensor details
        sensor_type = sensor.get("type")
        state = sensor.get("state", "N/A")
        y_offset = header_height + padding

        # Determine font for state based on panel size
        state_font = self.fonts["medium"] if not is_small_panel else self.fonts["small"]
        detail_font = self.fonts["small"]

        # Calculate space for NEW ALARM text at bottom if needed
        alarm_text_height = 0
        if is_newest_alarm:
            alarm_text_height = self.layout_params["sensor_row_height"] * 1.2

        # Calculate available height for details
        available_height = panel_height - header_height - padding * 2 - alarm_text_height

        # Render state with enhanced visibility
        if sensor_type in ["Outlet", "MultiOutlet"]:
            if "power" in sensor:
                power = safe_float(sensor["power"])
                if power is not None:
                    status = "On" if power > 0 else "Off"
                    # Improved color contrast
                    status_color = "#4CAF50" if power > 0 else "#F44336"  # Green for on, red for off
                    status_text = f"Status: {status}" if not is_small_panel else f"Status: {status} ({power}W)"
                    draw.text((x + padding, y + y_offset), status_text, font=state_font, fill=status_color)
                else:
                    draw.text((x + padding, y + y_offset), "Unknown", font=state_font, fill="#BDBDBD")
                y_offset += self.layout_params["sensor_row_height"]
            elif "powers" in sensor and isinstance(sensor["powers"], list):
                powers = sensor["powers"]
                max_outlets = 1 if is_small_panel else 2  # Show fewer outlets on small panels
                for j, power in enumerate(powers[:max_outlets]):
                    power_val = safe_float(power)
                    if power_val is not None:
                        status = "On" if power_val > 0 else "Off"
                        status_color = "#4CAF50" if power_val > 0 else "#F44336"
                        outlet_text = f"Out {j + 1}: {status}" if is_small_panel else f"Outlet {j + 1}: {status} ({power_val}W)"
                        draw.text((x + padding, y + y_offset + j * self.layout_params["sensor_row_height"]),
                                  outlet_text, font=state_font, fill=status_color)
                    else:
                        draw.text((x + padding, y + y_offset + j * self.layout_params["sensor_row_height"]),
                                  f"Out {j + 1}: Unknown" if is_small_panel else f"Outlet {j + 1}: Unknown",
                                  font=state_font, fill="#BDBDBD")
                y_offset += len(powers[:max_outlets]) * self.layout_params["sensor_row_height"]
            else:
                draw.text((x + padding, y + y_offset), "Unknown", font=state_font, fill="#BDBDBD")
                y_offset += self.layout_params["sensor_row_height"]
        else:
            if sensor_type in ["THSensor", "COSmokeSensor"] and isinstance(state, dict):
                # Improved smoke/CO sensor state display
                main_state, detail_reason = format_smoke_state(state)

                # Set color based on main state
                if main_state == "Alarm":
                    state_color = "#F44336"  # Red for alarm

                    # Create background for alarm state
                    state_text = f"State: {main_state}"
                    if not is_small_panel:
                        text_width = self._get_text_width(draw, state_text, state_font)
                        text_height = self.layout_params["sensor_row_height"]

                        # Background pill for alarm
                        draw.rectangle(
                            [(x + padding - 4, y + y_offset - 2),
                             (x + padding + text_width + 4, y + y_offset + text_height)],
                            fill="#B71C1C"  # Dark red background
                        )
                        draw.text((x + padding, y + y_offset), state_text, font=state_font, fill="#FFFFFF")
                    else:
                        draw.text((x + padding, y + y_offset), main_state, font=state_font, fill=state_color)
                elif main_state == "Silenced":
                    state_color = "#FFC107"  # Amber for silenced
                    draw.text((x + padding, y + y_offset),
                              f"State: {main_state}" if not is_small_panel else main_state,
                              font=state_font, fill=state_color)
                else:
                    state_color = "#4CAF50"  # Green for normal
                    draw.text((x + padding, y + y_offset),
                              f"State: {main_state}" if not is_small_panel else main_state,
                              font=state_font, fill=state_color)

                y_offset += self.layout_params["sensor_row_height"]

                # Show detail reason if present
                if detail_reason and y_offset < y + panel_height - padding - alarm_text_height:
                    draw.text((x + padding, y + y_offset), detail_reason, font=detail_font, fill="#FFFFFF")
                    y_offset += self.layout_params["sensor_row_height"]

            elif isinstance(state, str) and state.lower() in ["open", "motion"]:
                # Active alarm state - enhanced visibility
                state_text = state.upper()

                # Create a background for important states for better visibility
                text_width = self._get_text_width(draw, state_text if is_small_panel else f"State: {state_text}",
                                                  self.fonts["large"] if not is_small_panel else self.fonts["medium"])
                text_height = self.layout_params["sensor_row_height"] * (1.2 if not is_small_panel else 1)

                # Background pill shape for alarm state
                draw.rectangle(
                    [(x + padding - 4, y + y_offset - 2),
                     (x + padding + text_width + 4, y + y_offset + text_height)],
                    fill="#B71C1C"  # Dark red background
                )

                # State text with improved contrast
                state_font_to_use = self.fonts["large"] if not is_small_panel else self.fonts["medium"]
                draw.text((x + padding, y + y_offset),
                          f"State: {state_text}" if not is_small_panel else state_text,
                          font=state_font_to_use, fill="#FFFFFF")  # White text for contrast
                y_offset += self.layout_params["sensor_row_height"] * (1.5 if not is_small_panel else 1.2)
            elif isinstance(state, str) and state.lower() in ["closed", "no motion"]:
                # Normal state with modern color
                state_text = state if not is_small_panel else "CLOSED" if state.lower() == "closed" else "NO MOTION"
                state_color = "#4CAF50"  # Material Design green
                draw.text((x + padding, y + y_offset),
                          f"State: {state_text}" if not is_small_panel else state_text,
                          font=state_font, fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]
            else:
                # Default state
                state_text = str(state)
                state_color = "#FFFFFF"
                draw.text((x + padding, y + y_offset),
                          f"State: {state_text}" if not is_small_panel else state_text,
                          font=state_font, fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]

        # Battery indicator (inline implementation instead of calling a separate method)
        if "battery" in sensor:
            battery_value = map_battery_value(safe_int(sensor["battery"]))
            if battery_value is not None and y_offset < y + panel_height - padding - alarm_text_height:
                # Battery colors based on level - updated thresholds
                if battery_value <= 15:
                    batt_color = "#F44336"  # Red for very low battery
                elif battery_value <= 25:
                    batt_color = "#FF9800"  # Orange for low battery
                elif battery_value <= 50:
                    batt_color = "#FFC107"  # Amber for medium battery
                else:
                    batt_color = "#4CAF50"  # Green for good battery

                # Draw battery text
                batt_text = f"Batt: {battery_value}%" if is_small_panel else f"Battery: {battery_value}%"
                draw.text((x + padding, y + y_offset), batt_text, font=detail_font, fill=batt_color)

                # Draw battery icon if there's room
                text_width = self._get_text_width(draw, batt_text, detail_font)
                icon_x = x + padding + text_width + 10

                if icon_x + 30 <= x + panel_width - padding:
                    # Battery outline
                    bar_width = 25
                    bar_height = 12

                    # Draw the battery body
                    draw.rectangle(
                        [(icon_x, y + y_offset + 2),
                         (icon_x + bar_width, y + y_offset + bar_height)],
                        outline="#FFFFFF",
                        fill="#263238"
                    )

                    # Draw the battery terminal
                    draw.rectangle(
                        [(icon_x + bar_width, y + y_offset + 4),
                         (icon_x + bar_width + 2, y + y_offset + bar_height - 2)],
                        fill="#FFFFFF"
                    )

                    # Draw the filled part based on percentage
                    if battery_value > 0:
                        fill_width = max(2, int((bar_width - 2) * battery_value / 100))
                        draw.rectangle(
                            [(icon_x + 1, y + y_offset + 3),
                             (icon_x + 1 + fill_width, y + y_offset + bar_height - 1)],
                            fill=batt_color
                        )

                y_offset += self.layout_params["sensor_row_height"]
            elif battery_value is None and sensor[
                "battery"] is None and y_offset < y + panel_height - padding - alarm_text_height:
                # Handle case where battery is explicitly null
                draw.text((x + padding, y + y_offset), "Battery: Not Available", font=detail_font, fill="#BDBDBD")
                y_offset += self.layout_params["sensor_row_height"]

        # Signal strength indicator (inline implementation) - UPDATED THRESHOLDS
        if "signal" in sensor:
            signal_value = safe_int(sensor["signal"])
            if signal_value is not None and y_offset < y + panel_height - padding - alarm_text_height:
                # Signal colors based on updated strength thresholds
                if signal_value < -115:
                    signal_color = "#F44336"  # Red for very weak signal (alarm)
                elif signal_value < -105:
                    signal_color = "#FF9800"  # Orange for weak signal
                elif signal_value < -85:
                    signal_color = "#FFC107"  # Amber for medium signal
                elif signal_value < -70:
                    signal_color = "#8BC34A"  # Light green for good signal
                else:
                    signal_color = "#4CAF50"  # Green for excellent signal

                # Draw signal text
                signal_text = f"Sig: {signal_value} dBm" if is_small_panel else f"Signal: {signal_value} dBm"
                draw.text((x + padding, y + y_offset), signal_text, font=detail_font, fill=signal_color)

                # Draw signal bars if there's room
                text_width = self._get_text_width(draw, signal_text, detail_font)
                icon_x = x + padding + text_width + 10

                if icon_x + 25 <= x + panel_width - padding:
                    # Calculate signal strength using updated ranges
                    # Map from -120 to -60 range to 0-100%
                    strength_pct = max(0, min(100, (signal_value + 120) * 100 / 60))

                    # Draw signal bars
                    bar_width = 3
                    bar_spacing = 2
                    bar_base_height = 10

                    for i in range(4):
                        bar_height = (i + 1) * bar_base_height / 4
                        bar_x = icon_x + i * (bar_width + bar_spacing)

                        # Determine if this bar should be filled based on signal strength
                        threshold = (i + 1) * 25  # 25%, 50%, 75%, 100%
                        bar_color = signal_color if strength_pct >= threshold else "#263238"

                        draw.rectangle(
                            [(bar_x, y + y_offset + (bar_base_height - bar_height)),
                             (bar_x + bar_width, y + y_offset + bar_base_height)],
                            fill=bar_color
                        )

                y_offset += self.layout_params["sensor_row_height"]

        # Temperature indicator for THSensors (inline implementation)
        if sensor_type == "THSensor" and sensor.get("temperature", "unknown") != "unknown":
            if y_offset < y + panel_height - padding - alarm_text_height:
                temp_value = sensor['temperature']
                temp_unit = sensor.get('temperatureUnit', 'F')

                # Temperature colors based on value
                try:
                    temp = float(temp_value)
                    if temp_unit == 'F':
                        if temp < 32:
                            temp_color = "#2196F3"  # Blue for cold
                        elif temp < 68:
                            temp_color = "#4CAF50"  # Green for cool
                        elif temp < 85:
                            temp_color = "#FFC107"  # Amber for warm
                        else:
                            temp_color = "#F44336"  # Red for hot
                    else:  # Celsius
                        if temp < 0:
                            temp_color = "#2196F3"  # Blue for cold
                        elif temp < 20:
                            temp_color = "#4CAF50"  # Green for cool
                        elif temp < 30:
                            temp_color = "#FFC107"  # Amber for warm
                        else:
                            temp_color = "#F44336"  # Red for hot
                except (ValueError, TypeError):
                    temp_color = "#FFFFFF"  # Default white if conversion fails

                # Draw temperature text
                temp_text = f"{temp_value}°{temp_unit}" if is_small_panel else f"Temp: {temp_value}°{temp_unit}"
                draw.text((x + padding, y + y_offset), temp_text, font=detail_font, fill=temp_color)

                y_offset += self.layout_params["sensor_row_height"]

        # Show humidity for THSensors if present
        if sensor_type == "THSensor" and sensor.get("humidity", "unknown") != "unknown":
            if y_offset < y + panel_height - padding - alarm_text_height:
                humidity = sensor['humidity']

                # Humidity colors based on value
                try:
                    hum = float(humidity)
                    if hum < 30:
                        hum_color = "#FFC107"  # Amber for dry
                    elif hum > 70:
                        hum_color = "#2196F3"  # Blue for humid
                    else:
                        hum_color = "#4CAF50"  # Green for ideal
                except (ValueError, TypeError):
                    hum_color = "#FFFFFF"  # Default white if conversion fails

                # Draw humidity text
                hum_text = f"{humidity}%" if is_small_panel else f"Humidity: {humidity}%"
                draw.text((x + padding, y + y_offset), hum_text, font=detail_font, fill=hum_color)

                y_offset += self.layout_params["sensor_row_height"]

        # Add NEW ALARM text at the bottom of the panel - moved as requested
        if is_newest_alarm:
            # Calculate position for bottom of panel
            alarm_y = y + panel_height - self.layout_params["sensor_row_height"] - padding

            # Background for alarm text
            alarm_text = "⚠ NEW ALARM ⚠"
            alarm_text_width = self._get_text_width(draw, alarm_text, self.fonts["medium"])

            # Center the text in the panel
            alarm_x = x + (panel_width - alarm_text_width) // 2

            # Draw background pill for alarm text
            draw.rectangle(
                [(alarm_x - 6, alarm_y - 2),
                 (alarm_x + alarm_text_width + 6, alarm_y + self.layout_params["sensor_row_height"])],
                fill="#FF6F00"  # Dark amber background
            )

            # Draw the alarm text - now at bottom of panel
            draw.text((alarm_x, alarm_y), alarm_text, font=self.fonts["medium"], fill="#FFFFFF")

    # Update the method in update_sensors that determines if sensors are in alarm state
    def update_sensors(self, sensors: List[Dict[str, Any]]) -> None:
        """
        Update the sensor data and determine which sensors are in alarm state.
        Detects new alarms for immediate display.
        Using updated thresholds for signal strength.

        Args:
            sensors: List of sensor data dictionaries
        """
        with self.render_lock:
            if not isinstance(sensors, list):
                logger.error("Invalid sensor data: not a list")
                return

            previous_alarm_ids = set(s.get("deviceId") for s in self.alarm_sensors if s.get("deviceId"))
            self.sensor_data = []
            self.alarm_sensors = []
            self.last_update_time = time.time()
            logger.info(f"Received {len(sensors)} sensors via WebSocket")

            cutoff_date = datetime.now() - timedelta(days=60)

            for s in sensors:
                if not s:
                    continue

                last_seen = s.get("last_seen")
                if last_seen == "never":
                    continue

                try:
                    last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                    if last_seen_date < cutoff_date:
                        continue
                except (ValueError, TypeError):
                    continue

                self.sensor_data.append(s)
                sensor_type = s.get("type")
                state = s.get("state")
                signal = safe_int(s.get("signal"))
                battery = safe_int(s.get("battery"))
                device_id = s.get("deviceId", "UnknownID")

                state_str = str(state).strip().lower() if state is not None and not isinstance(state, dict) else ""
                mapped_battery = map_battery_value(battery) if battery is not None else None

                is_alarm = False
                alarm_reason = []

                if sensor_type == "DoorSensor":
                    if state_str == "open":
                        is_alarm = True
                        alarm_reason.append("State is 'open'")
                    # Updated signal threshold to -115
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")
                    if mapped_battery is not None and mapped_battery <= 25:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 25%")
                    self.previous_states[device_id] = state_str

                elif sensor_type == "MotionSensor":
                    if state_str == "motion":
                        is_alarm = True
                        alarm_reason.append("State is 'motion'")
                    # Updated signal threshold to -115
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")
                    if mapped_battery is not None and mapped_battery <= 25:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 25%")

                elif sensor_type in ["THSensor", "COSmokeSensor"]:
                    if isinstance(state, dict):
                        # Check for any alarm conditions
                        if (state.get("smokeAlarm", False) or
                                state.get("gasAlarm", False) or
                                state.get("unexpected", False) or
                                state.get("highTempAlarm", False)):
                            is_alarm = True

                            # Add specific reason
                            if state.get("smokeAlarm", False):
                                alarm_reason.append("Smoke Detected")
                            if state.get("gasAlarm", False):
                                alarm_reason.append("CO Detected")
                            if state.get("highTempAlarm", False):
                                alarm_reason.append("High Temperature")
                            if state.get("unexpected", False):
                                alarm_reason.append("Sensor Error!")

                    # Updated battery and signal thresholds
                    if mapped_battery is not None and mapped_battery <= 25:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 25%")
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")

                if is_alarm:
                    self.alarm_sensors.append(s)

            current_alarm_ids = set(s.get("deviceId") for s in self.alarm_sensors if s.get("deviceId"))
            new_alarm_ids = current_alarm_ids - previous_alarm_ids

            if new_alarm_ids:
                self.new_alarm_triggered = True
                self.alarm_display_timer = time.time()
                self.newest_alarm_id = next(iter(new_alarm_ids))
                for s in self.alarm_sensors:
                    if s.get("deviceId") == self.newest_alarm_id:
                        logger.info(f"New alarm highlighted: {s.get('name', 'Unknown')} (ID: {self.newest_alarm_id})")
                        break

            self._update_pagination()
            self.last_frame = None
            logger.info(
                f"Updated: {len(self.sensor_data)} sensors, {len(self.alarm_sensors)} alarms, {self.total_pages} pages")

    def _render_alarm_view(self, draw: ImageDraw.ImageDraw) -> None:
        """Render the alarm view (placeholder implementation)."""
        padding = self.layout_params["padding"]
        banner_height = self.layout_params["banner_height"]
        draw.rectangle([(0, 0), (self.current_width, banner_height)], fill="#333333")
        draw.text((padding, padding), "ALARM VIEW", font=self.fonts["large"], fill="#ff5555")

        start_idx = 0
        end_idx = min(len(self.alarm_sensors), self.sensors_per_page)
        for i, sensor in enumerate(self.alarm_sensors[start_idx:end_idx]):
            x = padding + (i % self.layout_params["grid_cols"]) * (self.layout_params["panel_width"] + padding)
            y = banner_height + padding + (i // self.layout_params["grid_cols"]) * (self.layout_params["panel_height"] + padding)
            self._render_sensor_panel(draw, sensor, x, y)

    def _render_normal_view(self, draw: ImageDraw.ImageDraw) -> None:
        """Render the normal view (placeholder implementation)."""
        padding = self.layout_params["padding"]
        banner_height = self.layout_params["banner_height"]
        draw.rectangle([(0, 0), (self.current_width, banner_height)], fill="#333333")
        draw.text((padding, padding), f"DASHBOARD - Page {self.current_page + 1}/{self.total_pages}",
                 font=self.fonts["large"], fill="#ffffff")

        start_idx = self.current_page * self.sensors_per_page
        end_idx = min(start_idx + self.sensors_per_page, len(self.sensor_data))
        for i, sensor in enumerate(self.sensor_data[start_idx:end_idx]):
            x = padding + (i % self.layout_params["grid_cols"]) * (self.layout_params["panel_width"] + padding)
            y = banner_height + padding + (i // self.layout_params["grid_cols"]) * (self.layout_params["panel_height"] + padding)
            self._render_sensor_panel(draw, sensor, x, y)


def format_smoke_state(state: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """
    Format smoke/CO sensor state into user-friendly text and provide detail reason.

    Args:
        state: Sensor state dictionary

    Returns:
        Tuple containing (main_state, detail_reason)
        - main_state: "Normal" or "Alarm"
        - detail_reason: Specific reason for alarm or None if normal
    """
    if not isinstance(state, dict):
        return "Unknown", None

    # Check for alarm conditions
    if state.get("smokeAlarm", False):
        return "Alarm", "Smoke Detected"
    elif state.get("gasAlarm", False):
        return "Alarm", "CO Detected"
    elif state.get("highTempAlarm", False):
        return "Alarm", "High Temperature"
    elif state.get("unexpected", False):
        return "Alarm", "Sensor Not Installed Correctly"
    elif state.get("sLowBattery", False) or state.get("lowBattery", False):
        return "Alarm", "Low Battery"
    elif state.get("silence", False):
        return "Silenced", None
    else:
        return "Normal", None