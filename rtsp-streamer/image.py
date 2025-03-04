"""
Image manipulation utilities for the YoLink Dashboard RTSP Server.
"""
import logging
from typing import Tuple
from PIL import ImageDraw, ImageFont

logger = logging.getLogger(__name__)


def get_text_width(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont) -> int:
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


def load_fonts() -> Tuple[ImageFont.FreeTypeFont, ImageFont.FreeTypeFont]:
    """
    Load font resources for the dashboard.

    Returns:
        Tuple[ImageFont.FreeTypeFont, ImageFont.FreeTypeFont]: Tuple of (large_font, small_font)
    """
    try:
        font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 18)
    except OSError as e:
        logger.warning(f"Could not load DejaVu fonts, using default: {e}")
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()

    return font_large, font_small