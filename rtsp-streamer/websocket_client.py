"""
WebSocket client for receiving YoLink sensor data updates.
"""
import json
import time
import logging
import threading
from typing import Dict, Any, List
import websocket

logger = logging.getLogger(__name__)


class WebSocketClient(threading.Thread):
    """
    WebSocket client for receiving sensor data from the YoLink Dashboard server.
    """

    def __init__(self, url: str, renderer):
        """
        Initialize the WebSocket client.

        Args:
            url: WebSocket server URL
            renderer: DashboardRenderer instance to update with sensor data
        """
        super().__init__()
        self.url = url
        self.renderer = renderer
        self.ws = None
        self.daemon = True
        self.connected = False
        self.should_reconnect = True
        self.reconnect_delay = 2  # Initial reconnect delay in seconds
        self.max_reconnect_delay = 60  # Maximum reconnect delay

    def run(self) -> None:
        """
        Thread main function. Connects to WebSocket server and processes messages.
        """
        while self.should_reconnect:
            try:
                logger.info(f"Attempting to connect to WebSocket: {self.url}")
                self.ws = websocket.create_connection(self.url)
                self.connected = True
                logger.info(f"Connected to WebSocket: {self.url}")

                # Reset reconnect delay on successful connection
                self.reconnect_delay = 2

                # Process messages until disconnection
                self._process_messages()

            except Exception as e:
                logger.error(f"WebSocket connection failed: {e}")
                self.connected = False

                # Implement exponential backoff for reconnection
                time.sleep(self.reconnect_delay)
                self.reconnect_delay = min(self.reconnect_delay * 1.5, self.max_reconnect_delay)

    def _process_messages(self) -> None:
        """
        Process incoming WebSocket messages.
        """
        while self.connected:
            try:
                msg = self.ws.recv()
                logger.debug(f"Received WebSocket message: {msg}")

                try:
                    data = json.loads(msg)
                    if data.get("type") == "sensors-update":
                        sensors = data.get("sensors", [])
                        logger.info(f"Received {len(sensors)} sensors via WebSocket")
                        self.renderer.update_sensors(sensors)
                    else:
                        logger.debug(f"Ignored message type: {data.get('type')}")

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in WebSocket message: {e}. Raw message: {msg}")
                    continue

            except Exception as e:
                logger.error(f"Error processing WebSocket message: {e}")
                self.connected = False
                break

    def close(self) -> None:
        """
        Close the WebSocket connection.
        """
        self.should_reconnect = False
        self.connected = False
        if self.ws:
            try:
                self.ws.close()
                logger.info("WebSocket connection closed")
            except Exception as e:
                logger.error(f"Error closing WebSocket connection: {e}")