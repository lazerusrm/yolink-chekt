"""
Modern Dashboard UI rendering for the YoLink Dashboard RTSP Server.
Fully redesigned with a sleek, modern aesthetic matching the web interface.
Features polished card designs, gradient backgrounds, and improved visual indicators.

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
from PIL import Image, ImageDraw, ImageFont, ImageColor
import math

from data import safe_int, safe_float, map_battery_value, format_smoke_state

logger = logging.getLogger(__name__)

# Modern color palette based on Apple/X.com design
COLORS = {
    "bg_primary": "#000000",
    "bg_secondary": "#121212",
    "bg_card": "#1c1c1e",
    "bg_card_elevated": "#2c2c2e",
    "bg_gradient_start": "#1c1c1e",
    "bg_gradient_end": "#2c2c2e",
    "text_primary": "#ffffff",
    "text_secondary": "#8e8e93",
    "accent_primary": "#007aff",
    "accent_secondary": "#5ac8fa",
    "success": "#34c759",
    "warning": "#ff9500",
    "error": "#ff3b30",
    "dark_success": "#0a5d26",
    "dark_warning": "#c77700",
    "dark_error": "#b71c1c",
    "outline_light": "#8e8e93",
    "alarm_gradient_start": "#ff453a",
    "alarm_gradient_end": "#ff3b30",
    "alarm_outline": "#ff9f0a",
    "alarm_text_bg": "#b71c1c",
}


class DashboardRenderer:
    """
    Renders the dashboard UI with sensor information using a modern design system.
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

        # Dynamic sizing based on panel dimensions
        if self.current_width <= 640:  # Mobile profile
            base_font_size = max(12, int(panel_height / 12))
            title_font_size = max(16, int(panel_height / 8))
            xl_font_size = max(18, int(panel_height / 6))
        elif self.current_width <= 960:  # Low-res profile
            base_font_size = max(14, int(panel_height / 10))
            title_font_size = max(20, int(panel_height / 7))
            xl_font_size = max(26, int(panel_height / 5))
        else:  # Main profile
            base_font_size = max(16, int(panel_height / 9))
            title_font_size = max(22, int(panel_height / 6))
            xl_font_size = max(30, int(panel_height / 4))

        try:
            # First try SF Pro font for Apple-like UI
            fonts = {
                "xl": ImageFont.truetype("/usr/share/fonts/truetype/sf-pro/SF-Pro-Display-Bold.otf", xl_font_size),
                "large": ImageFont.truetype("/usr/share/fonts/truetype/sf-pro/SF-Pro-Display-Bold.otf", title_font_size),
                "medium": ImageFont.truetype("/usr/share/fonts/truetype/sf-pro/SF-Pro-Display-Semibold.otf", base_font_size + 2),
                "small": ImageFont.truetype("/usr/share/fonts/truetype/sf-pro/SF-Pro-Text-Regular.otf", base_font_size)
            }
        except OSError:
            try:
                # Fall back to DejaVu fonts
                fonts = {
                    "xl": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", xl_font_size),
                    "large": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", title_font_size),
                    "medium": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", base_font_size + 2),
                    "small": ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", base_font_size)
                }
            except OSError as e:
                logger.warning(f"Could not load fonts, using default: {e}")
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

        # Modern banner height with better responsiveness
        if height <= 360:
            banner_height = max(35, min(45, height // 8))
        elif height <= 720:
            banner_height = max(45, min(65, height // 10))
        else:
            banner_height = max(65, min(85, height // 12))

        # Adjust grid layout based on sensors_per_page and screen size
        if width <= 640:
            max_cols = 2
        elif width <= 960:
            max_cols = 3
        elif width <= 1366:
            max_cols = 4
        else:
            max_cols = 5

        # Modern spacing with better padding
        padding = max(8, min(20, height // 70))
        card_border_radius = max(6, min(12, padding // 2))  # Proportional border radius

        # Calculate optimal grid size
        grid_cols = min(max_cols, max(1, min(sensors_per_page, int(sensors_per_page ** 0.5) + 1)))
        grid_rows = (sensors_per_page + grid_cols - 1) // grid_cols

        # Calculate panel dimensions with proper spacing
        panel_width = max(220, (width - (grid_cols + 1) * padding) // grid_cols)
        panel_height = max(140, (height - banner_height - (grid_rows + 1) * padding) // grid_rows)

        # Modern proportions for internal elements
        title_height = max(24, min(40, panel_height // 5))
        sensor_row_height = max(18, min(32, (panel_height - title_height) // 5))

        layout_params = {
            "grid_cols": grid_cols,
            "grid_rows": grid_rows,
            "panel_width": panel_width,
            "panel_height": panel_height,
            "banner_height": banner_height,
            "padding": padding,
            "title_height": title_height,
            "sensor_row_height": sensor_row_height,
            "card_border_radius": card_border_radius,
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
                # Responsive sensor count based on screen size
                if width >= 1920 and height >= 1080:
                    self.sensors_per_page = 20
                elif width >= 1366 and height >= 768:
                    self.sensors_per_page = 15
                elif width >= 1280 and height >= 720:
                    self.sensors_per_page = 12
                elif width >= 960 and height >= 540:
                    self.sensors_per_page = 8
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
        Using updated thresholds for signal strength.
        Now handles additional sensor types: VibrationSensor, LockV2, Manipulator, Finger.

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

                # Handle various types of state values
                if isinstance(state, dict):
                    state_str = "complex"
                elif isinstance(state, list):
                    state_str = "multi"
                else:
                    state_str = str(state).strip().lower() if state is not None else ""

                mapped_battery = map_battery_value(battery) if battery is not None else None

                is_alarm = False
                alarm_reason = []

                # DoorSensor alarm detection
                if sensor_type == "DoorSensor":
                    if state_str == "open":
                        is_alarm = True
                        alarm_reason.append("Door Open")
                    # Updated signal threshold to -115
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")
                    if mapped_battery is not None and mapped_battery <= 20:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 20%")
                    self.previous_states[device_id] = state_str

                # MotionSensor alarm detection
                elif sensor_type == "MotionSensor":
                    if state_str in ["motion", "alert"]:
                        is_alarm = True
                        alarm_reason.append("Motion Detected")
                    # Updated signal threshold to -115
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")
                    if mapped_battery is not None and mapped_battery <= 20:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 20%")

                # VibrationSensor alarm detection
                elif sensor_type == "VibrationSensor":
                    if state_str == "alert":
                        is_alarm = True
                        alarm_reason.append("Vibration Detected")
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")
                    if mapped_battery is not None and mapped_battery <= 20:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 20%")

                # LockV2 alarm detection
                elif sensor_type == "LockV2":
                    if isinstance(state, dict):
                        if state.get("door") == "open":
                            is_alarm = True
                            alarm_reason.append("Door Open")
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")
                    if mapped_battery is not None and mapped_battery <= 20:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 20%")

                # LeakSensor alarm detection
                elif sensor_type == "LeakSensor":
                    if state_str == "leak":
                        is_alarm = True
                        alarm_reason.append("Leak Detected")
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")
                    if mapped_battery is not None and mapped_battery <= 20:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 20%")

                # THSensor and COSmokeSensor alarm detection
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
                    if mapped_battery is not None and mapped_battery <= 20:
                        is_alarm = True
                        alarm_reason.append(f"Battery {mapped_battery}% <= 20%")
                    if signal is not None and signal < -115:
                        is_alarm = True
                        alarm_reason.append(f"Signal {signal} < -115")

                # Add sensor to alarm list if any alarm conditions met
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
        Render a frame of the dashboard with modern styling.
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

            # Create gradient background
            image = self._create_gradient_background(width, height)
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

    def _create_gradient_background(self, width: int, height: int) -> Image.Image:
        """
        Create a gradient background image similar to our modern web UI.

        Args:
            width: Width of image
            height: Height of image

        Returns:
            PIL.Image: Background image with gradient
        """
        # Create a new blank image
        image = Image.new("RGB", (width, height), self._hex_to_rgb(COLORS["bg_primary"]))
        draw = ImageDraw.Draw(image)

        # Draw a subtle gradient from top-left to bottom-right
        for y in range(height):
            # Calculate gradient factor (0.0 to 1.0)
            factor = y / height
            # Interpolate between primary and secondary background colors
            r1, g1, b1 = self._hex_to_rgb(COLORS["bg_primary"])
            r2, g2, b2 = self._hex_to_rgb(COLORS["bg_secondary"])
            r = int(r1 + (r2 - r1) * factor)
            g = int(g1 + (g2 - g1) * factor)
            b = int(b1 + (b2 - b1) * factor)
            # Draw a horizontal line with this color
            draw.line([(0, y), (width, y)], fill=(r, g, b))

        return image

    def _hex_to_rgb(self, hex_color: str) -> Tuple[int, int, int]:
        """
        Convert hex color to RGB tuple.

        Args:
            hex_color: Color in hex format (e.g. "#FF0000")

        Returns:
            Tuple[int, int, int]: RGB values
        """
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

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

    def _draw_rounded_rectangle(self, draw: ImageDraw.ImageDraw, xy: Tuple[int, int, int, int],
                               radius: int, fill=None, outline=None, width: int = 1) -> None:
        """
        Draw a rounded rectangle.

        Args:
            draw: PIL ImageDraw object
            xy: Rectangle coordinates (x0, y0, x1, y1)
            radius: Corner radius
            fill: Fill color
            outline: Outline color
            width: Outline width
        """
        x0, y0, x1, y1 = xy

        # Draw main rectangle
        draw.rectangle([(x0 + radius, y0), (x1 - radius, y1)], fill=fill)
        draw.rectangle([(x0, y0 + radius), (x1, y1 - radius)], fill=fill)

        # Draw four corners
        draw.pieslice([(x0, y0), (x0 + radius * 2, y0 + radius * 2)], 180, 270, fill=fill)
        draw.pieslice([(x1 - radius * 2, y0), (x1, y0 + radius * 2)], 270, 0, fill=fill)
        draw.pieslice([(x0, y1 - radius * 2), (x0 + radius * 2, y1)], 90, 180, fill=fill)
        draw.pieslice([(x1 - radius * 2, y1 - radius * 2), (x1, y1)], 0, 90, fill=fill)

        # Draw outline if needed
        if outline:
            self._draw_rounded_rectangle_outline(draw, xy, radius, outline, width)

    def _draw_rounded_rectangle_outline(self, draw: ImageDraw.ImageDraw, xy: Tuple[int, int, int, int],
                                      radius: int, outline, width: int = 1) -> None:
        """
        Draw just the outline of a rounded rectangle.

        Args:
            draw: PIL ImageDraw object
            xy: Rectangle coordinates (x0, y0, x1, y1)
            radius: Corner radius
            outline: Outline color
            width: Outline width
        """
        x0, y0, x1, y1 = xy

        # Draw lines
        for i in range(width):
            offset = i
            # Top line
            draw.line([(x0 + radius, y0 + offset), (x1 - radius, y0 + offset)], fill=outline)
            # Bottom line
            draw.line([(x0 + radius, y1 - offset), (x1 - radius, y1 - offset)], fill=outline)
            # Left line
            draw.line([(x0 + offset, y0 + radius), (x0 + offset, y1 - radius)], fill=outline)
            # Right line
            draw.line([(x1 - offset, y0 + radius), (x1 - offset, y1 - radius)], fill=outline)

        # Draw arcs for corners
        for i in range(width):
            offset = i
            # Top-left
            draw.arc([(x0 + offset, y0 + offset), (x0 + radius * 2 - offset, y0 + radius * 2 - offset)], 180, 270, fill=outline)
            # Top-right
            draw.arc([(x1 - radius * 2 + offset, y0 + offset), (x1 - offset, y0 + radius * 2 - offset)], 270, 0, fill=outline)
            # Bottom-left
            draw.arc([(x0 + offset, y1 - radius * 2 + offset), (x0 + radius * 2 - offset, y1 - offset)], 90, 180, fill=outline)
            # Bottom-right
            draw.arc([(x1 - radius * 2 + offset, y1 - radius * 2 + offset), (x1 - offset, y1 - offset)], 0, 90, fill=outline)

    def _draw_progress_bar(self, draw: ImageDraw.ImageDraw, x: int, y: int, width: int, height: int,
                         progress: float, bg_color: str, fill_color: str, outline_color: str = None) -> None:
        """
        Draw a modern progress bar.

        Args:
            draw: PIL ImageDraw object
            x: X coordinate
            y: Y coordinate
            width: Width of progress bar
            height: Height of progress bar
            progress: Progress value (0.0 to 1.0)
            bg_color: Background color
            fill_color: Fill color
            outline_color: Optional outline color
        """
        # Draw background
        self._draw_rounded_rectangle(draw, (x, y, x + width, y + height), height // 2,
                                   fill=bg_color, outline=outline_color)

        # Draw filled portion
        if progress > 0:
            fill_width = max(height, int(width * progress))
            fill_width = min(fill_width, width)  # Ensure we don't exceed the bar width
            self._draw_rounded_rectangle(draw, (x, y, x + fill_width, y + height),
                                       height // 2, fill=fill_color)

    def _draw_battery_icon(self, draw: ImageDraw.ImageDraw, x: int, y: int,
                        percentage: int, width: int = 24, height: int = 12) -> None:
        """
        Draw a modern battery icon.

        Args:
            draw: PIL ImageDraw object
            x: X coordinate
            y: Y coordinate
            percentage: Battery percentage (0-100)
            width: Width of battery
            height: Height of battery
        """
        # Set color based on percentage
        if percentage <= 20:
            color = COLORS["error"]
        elif percentage <= 50:
            color = COLORS["warning"]
        else:
            color = COLORS["success"]

        # Battery body
        body_width = width - 2
        self._draw_rounded_rectangle(draw, (x, y, x + body_width, y + height),
                                   radius=height // 4,
                                   fill=self._hex_to_rgb(COLORS["bg_card_elevated"]),
                                   outline=self._hex_to_rgb(COLORS["text_primary"]))

        # Battery terminal
        terminal_width = max(2, width // 12)
        terminal_height = max(4, height // 3)
        draw.rectangle(
            [(x + body_width, y + (height - terminal_height) // 2),
             (x + body_width + terminal_width, y + (height + terminal_height) // 2)],
            fill=self._hex_to_rgb(COLORS["text_primary"])
        )

        # Fill level
        if percentage > 0:
            fill_width = max(3, int((body_width - 2) * percentage / 100))
            self._draw_rounded_rectangle(
                draw,
                (x + 1, y + 1, x + 1 + fill_width, y + height - 1),
                radius=height // 6,
                fill=self._hex_to_rgb(color)
            )

    def _draw_signal_icon(self, draw: ImageDraw.ImageDraw, x: int, y: int,
                       signal_strength: int, width: int = 24, height: int = 12) -> None:
        """
        Draw a modern signal strength icon.

        Args:
            draw: PIL ImageDraw object
            x: X coordinate
            y: Y coordinate
            signal_strength: Signal strength value in dBm (typically -30 to -120)
            width: Width of signal icon
            height: Height of signal icon
        """
        # Convert dBm to percentage (roughly -50 dBm → 100%, -120 dBm → 0%)
        percentage = max(0, min(100, (signal_strength + 120) * 100 / 70))

        # Set color based on signal strength
        if signal_strength < -115:
            color = COLORS["error"]
        elif signal_strength < -90:
            color = COLORS["warning"]
        else:
            color = COLORS["success"]

        # Number of bars
        bar_count = 4
        bar_width = max(2, (width - (bar_count - 1)) // bar_count)
        spacing = 1

        for i in range(bar_count):
            # Calculate if this bar should be filled
            bar_threshold = (i + 1) * (100 / bar_count)
            bar_color = color if percentage >= bar_threshold else COLORS["bg_card_elevated"]

            # Calculate bar height (increasing heights)
            bar_height = int(height * (i + 1) / bar_count)

            # Draw the bar
            draw.rectangle(
                [(x + i * (bar_width + spacing), y + (height - bar_height)),
                 (x + i * (bar_width + spacing) + bar_width, y + height)],
                fill=self._hex_to_rgb(bar_color)
            )

    def _render_sensor_panel(self, draw: ImageDraw.ImageDraw, sensor: Dict[str, Any],
                             x: int, y: int) -> None:
        """
        Render a single sensor panel with modern visual indicators.
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
        border_radius = self.layout_params["card_border_radius"]

        # Determine if we're in a small resolution mode
        is_small_panel = panel_width < 220 or panel_height < 150

        device_id = sensor.get("deviceId", "")
        is_newest_alarm = device_id == self.newest_alarm_id
        is_in_alarm = device_id in [s.get("deviceId") for s in self.alarm_sensors]

        # Modern styling based on alarm state
        if is_newest_alarm:
            # Newest alarm - vibrant colors with pulsing effect
            card_fill = self._hex_to_rgb(COLORS["dark_error"])
            header_fill = self._hex_to_rgb(COLORS["error"])
            outline_color = self._hex_to_rgb(COLORS["alarm_outline"])
            outline_width = 3 if is_small_panel else 4
        elif is_in_alarm:
            # Alarm state - strong but less intense than newest
            card_fill = self._hex_to_rgb(COLORS["dark_error"])
            header_fill = self._hex_to_rgb(COLORS["error"])
            outline_color = self._hex_to_rgb(COLORS["error"])
            outline_width = 2 if is_small_panel else 3
        else:
            # Normal state - modern dark theme
            card_fill = self._hex_to_rgb(COLORS["bg_card"])
            header_fill = self._hex_to_rgb(COLORS["bg_card_elevated"])
            outline_color = self._hex_to_rgb(COLORS["outline_light"])
            outline_width = 1

        # Draw card background with rounded corners
        self._draw_rounded_rectangle(
            draw,
            (x, y, x + panel_width, y + panel_height),
            radius=border_radius,
            fill=card_fill,
            outline=outline_color,
            width=outline_width
        )

        # Draw header with slightly elevated color
        header_height = title_height + padding
        draw.rectangle(
            [(x, y), (x + panel_width, y + header_height)],
            fill=header_fill
        )

        # Rounded corners for top of the header
        draw.pieslice(
            [(x, y), (x + border_radius * 2, y + border_radius * 2)],
            180, 270, fill=header_fill
        )
        draw.pieslice(
            [(x + panel_width - border_radius * 2, y), (x + panel_width, y + border_radius * 2)],
            270, 0, fill=header_fill
        )

        # Get sensor name and truncate as needed
        sensor_name = sensor.get("name", "Unknown")
        sensor_name = self._truncate_text(draw, sensor_name,
                                          self.fonts["large" if not is_small_panel else "medium"],
                                          panel_width - (padding * 2))

        # Render sensor name with improved positioning
        name_font = self.fonts["large" if not is_small_panel else "medium"]
        draw.text((x + padding, y + padding), sensor_name, font=name_font, fill=COLORS["text_primary"])

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

        # Draw appropriate icon based on sensor type
        icon_size = min(24, panel_width // 10)
        icon_x = x + panel_width - icon_size - padding
        icon_y = y + padding

        # More detailed sensor type icon rendering
        if sensor_type == "DoorSensor":
            # Draw a simple door icon
            door_width = icon_size
            door_height = icon_size
            draw.rectangle(
                [(icon_x, icon_y), (icon_x + door_width, icon_y + door_height)],
                outline=self._hex_to_rgb(COLORS["accent_primary"]),
                width=2
            )
            # Door handle
            handle_size = max(2, door_width // 6)
            draw.ellipse(
                [(icon_x + door_width - handle_size * 2, icon_y + door_height // 2 - handle_size),
                 (icon_x + door_width - handle_size, icon_y + door_height // 2 + handle_size)],
                fill=self._hex_to_rgb(COLORS["accent_primary"])
            )
        elif sensor_type == "MotionSensor":
            # Draw a motion icon (radiating waves)
            center_x = icon_x + icon_size // 2
            center_y = icon_y + icon_size // 2
            # Draw person
            head_size = max(3, icon_size // 4)
            draw.ellipse(
                [(center_x - head_size // 2, center_y - head_size * 1.5),
                 (center_x + head_size // 2, center_y - head_size // 2)],
                outline=self._hex_to_rgb(COLORS["accent_primary"]),
                width=2
            )
            # Body
            draw.line(
                [(center_x, center_y - head_size // 2), (center_x, center_y + head_size)],
                fill=self._hex_to_rgb(COLORS["accent_primary"]),
                width=2
            )
            # Arms
            draw.line(
                [(center_x - head_size, center_y), (center_x + head_size, center_y)],
                fill=self._hex_to_rgb(COLORS["accent_primary"]),
                width=2
            )
            # Legs
            draw.line(
                [(center_x, center_y + head_size), (center_x - head_size, center_y + head_size * 2)],
                fill=self._hex_to_rgb(COLORS["accent_primary"]),
                width=2
            )
            draw.line(
                [(center_x, center_y + head_size), (center_x + head_size, center_y + head_size * 2)],
                fill=self._hex_to_rgb(COLORS["accent_primary"]),
                width=2
            )
        elif sensor_type == "THSensor":
            # Draw a thermometer icon
            center_x = icon_x + icon_size // 2
            center_y = icon_y + icon_size // 2
            bulb_size = max(4, icon_size // 3)
            stem_width = max(2, bulb_size // 3)
            stem_height = icon_size - bulb_size

            # Stem
            draw.rectangle(
                [(center_x - stem_width // 2, center_y - stem_height),
                 (center_x + stem_width // 2, center_y)],
                outline=self._hex_to_rgb(COLORS["accent_primary"]),
                width=1
            )

            # Bulb
            draw.ellipse(
                [(center_x - bulb_size // 2, center_y - bulb_size // 2),
                 (center_x + bulb_size // 2, center_y + bulb_size // 2)],
                outline=self._hex_to_rgb(COLORS["accent_primary"]),
                fill=self._hex_to_rgb(COLORS["accent_secondary"])
            )
        elif sensor_type == "LeakSensor":
            # Draw a water droplet icon
            center_x = icon_x + icon_size // 2
            center_y = icon_y + icon_size // 2
            radius = icon_size // 2

            # Draw a teardrop shape
            points = []
            for angle in range(0, 360, 10):
                rad = math.radians(angle)
                # Make the bottom part circular, the top part pointed
                if 45 < angle < 315:
                    dist = radius
                else:
                    # Create a point at the top
                    factor = 1 - (abs(angle - 180) / 180) * 0.5
                    dist = radius * factor

                px = center_x + dist * math.sin(rad)
                py = center_y + dist * math.cos(rad)
                points.append((px, py))

            draw.polygon(points, outline=self._hex_to_rgb(COLORS["accent_primary"]), fill=self._hex_to_rgb(COLORS["accent_secondary"]))
        elif sensor_type == "COSmokeSensor":
            # Draw a smoke alarm icon
            center_x = icon_x + icon_size // 2
            center_y = icon_y + icon_size // 2
            radius = icon_size // 2

            # Circle
            draw.ellipse(
                [(center_x - radius, center_y - radius),
                 (center_x + radius, center_y + radius)],
                outline=self._hex_to_rgb(COLORS["accent_primary"]),
                width=2
            )

            # CO text inside
            co_text = "CO"
            text_width = self._get_text_width(draw, co_text, detail_font)
            draw.text(
                (center_x - text_width // 2, center_y - radius // 2),
                co_text,
                font=detail_font,
                fill=self._hex_to_rgb(COLORS["accent_primary"])
            )

            # Wavy smoke lines coming out
            wave_width = radius * 3 // 4
            for offset in range(3):
                y_pos = center_y - radius - 2 - offset * 3
                draw.arc(
                    [(center_x - wave_width, y_pos - 3),
                     (center_x + wave_width, y_pos + 3)],
                    0, 180,
                    fill=self._hex_to_rgb(COLORS["accent_primary"]),
                    width=1
                )

        # Render state with enhanced visibility
        if sensor_type in ["Outlet", "MultiOutlet"]:
            if "power" in sensor:
                power = safe_float(sensor["power"])
                if power is not None:
                    status = "On" if power > 0 else "Off"
                    # Improved color contrast
                    status_color = COLORS["success"] if power > 0 else COLORS["error"]
                    status_text = f"Status: {status}" if not is_small_panel else f"Status: {status} ({power}W)"
                    draw.text((x + padding, y + y_offset), status_text, font=state_font, fill=status_color)
                else:
                    draw.text((x + padding, y + y_offset), "Unknown", font=state_font, fill=COLORS["text_secondary"])
                y_offset += self.layout_params["sensor_row_height"]
            elif "powers" in sensor and isinstance(sensor["powers"], list):
                powers = sensor["powers"]
                max_outlets = 1 if is_small_panel else 2  # Show fewer outlets on small panels
                for j, power in enumerate(powers[:max_outlets]):
                    power_val = safe_float(power)
                    if power_val is not None:
                        status = "On" if power_val > 0 else "Off"
                        status_color = COLORS["success"] if power_val > 0 else COLORS["error"]
                        outlet_text = f"Out {j + 1}: {status}" if is_small_panel else f"Outlet {j + 1}: {status} ({power_val}W)"
                        draw.text((x + padding, y + y_offset + j * self.layout_params["sensor_row_height"]),
                                  outlet_text, font=state_font, fill=status_color)
                    else:
                        draw.text((x + padding, y + y_offset + j * self.layout_params["sensor_row_height"]),
                                  f"Out {j + 1}: Unknown" if is_small_panel else f"Outlet {j + 1}: Unknown",
                                  font=state_font, fill=COLORS["text_secondary"])
                y_offset += len(powers[:max_outlets]) * self.layout_params["sensor_row_height"]
            else:
                draw.text((x + padding, y + y_offset), "Unknown", font=state_font, fill=COLORS["text_secondary"])
                y_offset += self.layout_params["sensor_row_height"]
        else:
            if sensor_type in ["THSensor", "COSmokeSensor"] and isinstance(state, dict):
                # Improved smoke/CO sensor state display
                main_state, detail_reason = format_smoke_state(state)

                # Set color based on main state
                if main_state == "Alarm":
                    state_color = COLORS["error"]

                    # Create background for alarm state
                    state_text = f"State: {main_state}"
                    if not is_small_panel:
                        text_width = self._get_text_width(draw, state_text, state_font)
                        text_height = self.layout_params["sensor_row_height"]

                        # Background pill for alarm
                        self._draw_rounded_rectangle(
                            draw,
                            (x + padding - 4, y + y_offset - 2,
                             x + padding + text_width + 4, y + y_offset + text_height),
                            radius=text_height // 3,
                            fill=self._hex_to_rgb(COLORS["alarm_text_bg"])
                        )
                        draw.text((x + padding, y + y_offset), state_text, font=state_font, fill=COLORS["text_primary"])
                    else:
                        draw.text((x + padding, y + y_offset), main_state, font=state_font, fill=state_color)
                elif main_state == "Silenced":
                    state_color = COLORS["warning"]
                    draw.text((x + padding, y + y_offset),
                              f"State: {main_state}" if not is_small_panel else main_state,
                              font=state_font, fill=state_color)
                else:
                    state_color = COLORS["success"]
                    draw.text((x + padding, y + y_offset),
                              f"State: {main_state}" if not is_small_panel else main_state,
                              font=state_font, fill=state_color)

                y_offset += self.layout_params["sensor_row_height"]

                # Show detail reason if present
                if detail_reason and y_offset < y + panel_height - padding - alarm_text_height:
                    draw.text((x + padding, y + y_offset), detail_reason, font=detail_font, fill=COLORS["text_primary"])
                    y_offset += self.layout_params["sensor_row_height"]

            elif isinstance(state, str) and state.lower() in ["open", "motion", "alert", "leak"]:
                # Active alarm state - enhanced visibility with pill background
                state_text = state.upper()

                # Create a background for important states for better visibility
                text_width = self._get_text_width(draw, state_text if is_small_panel else f"State: {state_text}",
                                                  self.fonts["large"] if not is_small_panel else self.fonts["medium"])
                text_height = self.layout_params["sensor_row_height"] * (1.2 if not is_small_panel else 1)

                # Background pill shape for alarm state
                self._draw_rounded_rectangle(
                    draw,
                    (x + padding - 4, y + y_offset - 2,
                     x + padding + text_width + 4, y + y_offset + text_height),
                    radius=text_height // 3,
                    fill=self._hex_to_rgb(COLORS["alarm_text_bg"])
                )

                # State text with improved contrast
                state_font_to_use = self.fonts["large"] if not is_small_panel else self.fonts["medium"]
                draw.text((x + padding, y + y_offset),
                          f"State: {state_text}" if not is_small_panel else state_text,
                          font=state_font_to_use, fill=COLORS["text_primary"])  # White text for contrast
                y_offset += self.layout_params["sensor_row_height"] * (1.5 if not is_small_panel else 1.2)
            elif isinstance(state, str) and state.lower() in ["closed", "no motion"]:
                # Normal state with modern color
                state_text = state if not is_small_panel else "CLOSED" if state.lower() == "closed" else "NO MOTION"
                state_color = COLORS["success"]
                draw.text((x + padding, y + y_offset),
                          f"State: {state_text}" if not is_small_panel else state_text,
                          font=state_font, fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]
            else:
                # Default state
                state_text = str(state)
                state_color = COLORS["text_primary"]
                draw.text((x + padding, y + y_offset),
                          f"State: {state_text}" if not is_small_panel else state_text,
                          font=state_font, fill=state_color)
                y_offset += self.layout_params["sensor_row_height"]

        # Battery indicator with modern styling
        if "battery" in sensor:
            battery_value = map_battery_value(safe_int(sensor["battery"]))
            if battery_value is not None and y_offset < y + panel_height - padding - alarm_text_height:
                # Battery colors based on level
                if battery_value <= 15:
                    batt_color = COLORS["error"]  # Red for very low battery
                elif battery_value <= 25:
                    batt_color = COLORS["warning"]  # Orange for low battery
                else:
                    batt_color = COLORS["success"]  # Green for good battery

                # Draw battery text
                batt_text = f"Batt: {battery_value}%" if is_small_panel else f"Battery: {battery_value}%"
                draw.text((x + padding, y + y_offset), batt_text, font=detail_font, fill=batt_color)

                # Draw modern battery icon
                text_width = self._get_text_width(draw, batt_text, detail_font)
                icon_x = x + padding + text_width + 10

                if icon_x + 30 <= x + panel_width - padding:
                    self._draw_battery_icon(draw, icon_x, y + y_offset + 2, battery_value)

                y_offset += self.layout_params["sensor_row_height"]
            elif battery_value is None and sensor["battery"] is None and y_offset < y + panel_height - padding - alarm_text_height:
                # Handle case where battery is explicitly null
                draw.text((x + padding, y + y_offset), "Battery: Not Available", font=detail_font, fill=COLORS["text_secondary"])
                y_offset += self.layout_params["sensor_row_height"]

        # Signal strength indicator with modern styling
        if "signal" in sensor:
            signal_value = safe_int(sensor["signal"])
            if signal_value is not None and y_offset < y + panel_height - padding - alarm_text_height:
                # Signal colors based on updated strength thresholds
                if signal_value < -115:
                    signal_color = COLORS["error"]  # Red for very weak signal (alarm)
                elif signal_value < -90:
                    signal_color = COLORS["warning"]  # Orange for weak signal
                else:
                    signal_color = COLORS["success"]  # Green for good signal

                # Draw signal text
                signal_text = f"Sig: {signal_value} dBm" if is_small_panel else f"Signal: {signal_value} dBm"
                draw.text((x + padding, y + y_offset), signal_text, font=detail_font, fill=signal_color)

                # Draw modern signal bars
                text_width = self._get_text_width(draw, signal_text, detail_font)
                icon_x = x + padding + text_width + 10

                if icon_x + 25 <= x + panel_width - padding:
                    self._draw_signal_icon(draw, icon_x, y + y_offset + 2, signal_value)

                y_offset += self.layout_params["sensor_row_height"]

        # Temperature indicator for THSensors with modern styling
        if sensor_type == "THSensor" and sensor.get("temperature", "unknown") != "unknown":
            if y_offset < y + panel_height - padding - alarm_text_height:
                temp_value = sensor['temperature']
                temp_unit = sensor.get('temperatureUnit', 'F')

                # Temperature colors based on value
                try:
                    temp = float(temp_value)
                    if temp_unit == 'F':
                        if temp < 32:
                            temp_color = COLORS["accent_secondary"]  # Blue for cold
                        elif temp < 68:
                            temp_color = COLORS["success"]  # Green for cool
                        elif temp < 85:
                            temp_color = COLORS["warning"]  # Amber for warm
                        else:
                            temp_color = COLORS["error"]  # Red for hot
                    else:  # Celsius
                        if temp < 0:
                            temp_color = COLORS["accent_secondary"]  # Blue for cold
                        elif temp < 20:
                            temp_color = COLORS["success"]  # Green for cool
                        elif temp < 30:
                            temp_color = COLORS["warning"]  # Amber for warm
                        else:
                            temp_color = COLORS["error"]  # Red for hot
                except (ValueError, TypeError):
                    temp_color = COLORS["text_primary"]  # Default white if conversion fails

                # Draw temperature text
                temp_text = f"{temp_value}°{temp_unit}" if is_small_panel else f"Temp: {temp_value}°{temp_unit}"
                draw.text((x + padding, y + y_offset), temp_text, font=detail_font, fill=temp_color)

                y_offset += self.layout_params["sensor_row_height"]

        # Show humidity for THSensors with modern styling
        if sensor_type == "THSensor" and sensor.get("humidity", "unknown") != "unknown":
            if y_offset < y + panel_height - padding - alarm_text_height:
                humidity = sensor['humidity']

                # Humidity colors based on value
                try:
                    hum = float(humidity)
                    if hum < 30:
                        hum_color = COLORS["warning"]  # Amber for dry
                    elif hum > 70:
                        hum_color = COLORS["accent_secondary"]  # Blue for humid
                    else:
                        hum_color = COLORS["success"]  # Green for ideal
                except (ValueError, TypeError):
                    hum_color = COLORS["text_primary"]  # Default white if conversion fails

                # Draw humidity text
                hum_text = f"{humidity}%" if is_small_panel else f"Humidity: {humidity}%"
                draw.text((x + padding, y + y_offset), hum_text, font=detail_font, fill=hum_color)

                y_offset += self.layout_params["sensor_row_height"]

        # Add NEW ALARM text at the bottom of the panel
        if is_newest_alarm:
            # Calculate position for bottom of panel
            alarm_y = y + panel_height - self.layout_params["sensor_row_height"] - padding

            # Background for alarm text
            alarm_text = "⚠ NEW ALARM ⚠"
            alarm_text_width = self._get_text_width(draw, alarm_text, self.fonts["medium"])

            # Center the text in the panel
            alarm_x = x + (panel_width - alarm_text_width) // 2

            # Draw background pill for alarm text
            self._draw_rounded_rectangle(
                draw,
                (alarm_x - 8, alarm_y - 2,
                 alarm_x + alarm_text_width + 8, alarm_y + self.layout_params["sensor_row_height"]),
                radius=8,
                fill=self._hex_to_rgb(COLORS["dark_warning"])
            )

            # Draw the alarm text - now at bottom of panel
            draw.text((alarm_x, alarm_y), alarm_text, font=self.fonts["medium"], fill=COLORS["text_primary"])

    def _render_alarm_view(self, draw: ImageDraw.ImageDraw) -> None:
        """
        Render a view showing only sensors in alarm state.

        Args:
            draw: PIL ImageDraw object
        """
        width, height = self.current_width, self.current_height
        padding = self.layout_params["padding"]
        banner_height = self.layout_params["banner_height"]

        # Draw top banner with gradient effect
        for y in range(banner_height):
            # Calculate gradient factor
            factor = y / banner_height
            # Interpolate between colors
            r1, g1, b1 = self._hex_to_rgb(COLORS["error"])
            r2, g2, b2 = self._hex_to_rgb(COLORS["dark_error"])
            r = int(r1 + (r2 - r1) * factor)
            g = int(g1 + (g2 - g1) * factor)
            b = int(b1 + (b2 - b1) * factor)
            # Draw a horizontal line with this color
            draw.line([(0, y), (width, y)], fill=(r, g, b))

        # Draw alarm view title with icon
        header_text = "⚠️ ALARM VIEW ⚠️"
        draw.text((padding, padding), header_text, font=self.fonts["large"], fill=COLORS["text_primary"])

        # Draw alarm count
        count_text = f"{len(self.alarm_sensors)} Active Alarms"
        draw.text((width - padding - self._get_text_width(draw, count_text, self.fonts["medium"]), padding),
                 count_text, font=self.fonts["medium"], fill=COLORS["text_primary"])

        # Draw sensor panels - limit to visible sensors per page
        start_idx = 0
        end_idx = min(len(self.alarm_sensors), self.sensors_per_page)
        for i, sensor in enumerate(self.alarm_sensors[start_idx:end_idx]):
            x = padding + (i % self.layout_params["grid_cols"]) * (self.layout_params["panel_width"] + padding)
            y = banner_height + padding + (i // self.layout_params["grid_cols"]) * (self.layout_params["panel_height"] + padding)
            self._render_sensor_panel(draw, sensor, x, y)

        # Draw update time
        update_text = self._format_time_since_update()
        draw.text((padding, banner_height - padding - self._get_text_width(draw, update_text, self.fonts["small"])),
                 update_text, font=self.fonts["small"], fill=COLORS["text_secondary"])

    def _render_normal_view(self, draw: ImageDraw.ImageDraw) -> None:
        """
        Render the normal dashboard view showing all sensors.

        Args:
            draw: PIL ImageDraw object
        """
        width, height = self.current_width, self.current_height
        padding = self.layout_params["padding"]
        banner_height = self.layout_params["banner_height"]

        # Draw top banner with gradient effect
        for y in range(banner_height):
            # Calculate gradient factor
            factor = y / banner_height
            # Interpolate between colors
            r1, g1, b1 = self._hex_to_rgb(COLORS["accent_primary"])
            r2, g2, b2 = self._hex_to_rgb(COLORS["bg_card_elevated"])
            r = int(r1 + (r2 - r1) * factor)
            g = int(g1 + (g2 - g1) * factor)
            b = int(b1 + (b2 - b1) * factor)
            # Draw a horizontal line with this color
            draw.line([(0, y), (width, y)], fill=(r, g, b))

        # Draw dashboard title
        header_text = "YoLink Dashboard"
        draw.text((padding, padding), header_text, font=self.fonts["large"], fill=COLORS["text_primary"])

        # Draw pagination info
        page_text = f"Page {self.current_page + 1}/{self.total_pages}"
        draw.text((width - padding - self._get_text_width(draw, page_text, self.fonts["medium"]), padding),
                 page_text, font=self.fonts["medium"], fill=COLORS["text_primary"])

        # Draw sensor count
        count_text = f"{len(self.sensor_data)} Sensors"
        draw.text((width - padding - self._get_text_width(draw, count_text, self.fonts["small"]),
                  padding + self.layout_params["sensor_row_height"]),
                 count_text, font=self.fonts["small"], fill=COLORS["text_secondary"])

        # Draw sensor panels for current page
        start_idx = self.current_page * self.sensors_per_page
        end_idx = min(start_idx + self.sensors_per_page, len(self.sensor_data))
        for i, sensor in enumerate(self.sensor_data[start_idx:end_idx]):
            x = padding + (i % self.layout_params["grid_cols"]) * (self.layout_params["panel_width"] + padding)
            y = banner_height + padding + (i // self.layout_params["grid_cols"]) * (self.layout_params["panel_height"] + padding)
            self._render_sensor_panel(draw, sensor, x, y)

        # Draw update time
        update_text = self._format_time_since_update()
        draw.text((padding, banner_height - padding - self._get_text_width(draw, update_text, self.fonts["small"])),
                 update_text, font=self.fonts["small"], fill=COLORS["text_secondary"])


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