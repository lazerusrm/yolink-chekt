"""
Data processing utilities for the YoLink Dashboard RTSP Server.
"""
from typing import Optional, Dict, Any, Union


def safe_int(val: Any) -> Optional[int]:
    """
    Convert value to int safely, returning None if conversion fails.

    Args:
        val: Value to convert to integer

    Returns:
        int or None: Converted integer or None if conversion fails
    """
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def safe_float(val: Any) -> Optional[float]:
    """
    Convert value to float safely, returning None if conversion fails.

    Args:
        val: Value to convert to float

    Returns:
        float or None: Converted float or None if conversion fails
    """
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def map_battery_value(raw_value: Any) -> Optional[int]:
    """
    Maps raw battery values (0-4) to percentage values (0-100).

    Args:
        raw_value: Raw battery value (0-4)

    Returns:
        int or None: Battery percentage or None if invalid value
    """
    raw_value = safe_int(raw_value)
    if raw_value is None or raw_value < 0 or raw_value > 4:
        return None
    return {0: 0, 1: 25, 2: 50, 3: 75, 4: 100}[raw_value]


def format_smoke_state(state: Union[Dict[str, Any], Any]) -> str:
    """
    Format smoke/gas alarm state for display.

    Args:
        state: State dictionary or value

    Returns:
        str: Formatted state string
    """
    if not isinstance(state, dict):
        return str(state)

    if state.get("smokeAlarm", False):
        return "SMOKE ALARM"
    if state.get("gasAlarm", False):
        return "GAS ALARM"
    if state.get("unexpected", False):
        return "ALERT"

    return "normal"