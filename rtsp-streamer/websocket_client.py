"""
Robust WebSocket client for receiving YoLink sensor data updates.
Provides reliable reconnection, error handling, and data processing.
"""
import json
import random
import time
import logging
import threading
import queue
from typing import Dict, Any, List, Optional, Callable
import websocket

logger = logging.getLogger(__name__)


class WebSocketClient(threading.Thread):
    """
    WebSocket client for receiving sensor data from the YoLink Dashboard server.
    Features include:
    - Automatic reconnection with exponential backoff
    - Separate processing thread for improved responsiveness
    - Message buffering to handle high-throughput situations
    - Connection health monitoring
    """

    def __init__(self, url: str, renderer, initial_backoff=2, max_backoff=120):
        """
        Initialize the WebSocket client.

        Args:
            url: WebSocket server URL
            renderer: DashboardRenderer instance to update with sensor data
            initial_backoff: Initial reconnect delay in seconds
            max_backoff: Maximum reconnect delay in seconds
        """
        super().__init__(daemon=True)
        self.url = url
        self.renderer = renderer
        self.ws = None

        # Connection state
        self.connected = False
        self.should_reconnect = True
        self.reconnect_delay = initial_backoff  # Initial reconnect delay
        self.max_reconnect_delay = max_backoff  # Maximum reconnect delay

        # Message queue for processing
        self.message_queue = queue.Queue(maxsize=100)  # Limit queue size to prevent memory issues
        self.processor = None

        # Thread synchronization
        self.connect_lock = threading.RLock()

        # Health monitoring
        self.last_message_time = 0
        self.health_check_interval = 60  # seconds
        self.health_checker = None

        # Lifecycle management
        self.running = True

        # Statistics
        self.stats = {
            'messages_received': 0,
            'messages_processed': 0,
            'connection_attempts': 0,
            'successful_connections': 0,
            'connection_failures': 0,
            'last_error': None,
            'connect_time': 0,
            'process_time': 0
        }

    def run(self) -> None:
        """
        Main thread function. Connects to WebSocket server and manages connection.
        """
        logger.info(f"WebSocket client starting for {self.url}")

        # Add initial jitter to prevent thundering herd if multiple clients start at once
        time.sleep(self.reconnect_delay * (0.5 + random.random()))

        # Start message processor thread
        self._start_processor()

        # Start health checker
        self._start_health_checker()

        # Connection loop
        while self.running and self.should_reconnect:
            try:
                with self.connect_lock:
                    logger.info(f"Connecting to WebSocket: {self.url}")
                    self.stats['connection_attempts'] += 1

                    # Configure WebSocket with appropriate settings
                    self.ws = websocket.WebSocketApp(
                        self.url,
                        on_message=self._on_message,
                        on_error=self._on_error,
                        on_close=self._on_close,
                        on_open=self._on_open
                    )

                    # Connect with ping interval for keep-alive
                    self.ws.run_forever(
                        ping_interval=30,  # Send ping every 30 seconds
                        ping_timeout=10,   # Wait 10 seconds for pong response
                        reconnect=False    # We'll handle reconnection ourselves
                    )

                    # Connection has been closed - ws.run_forever has returned
                    self.connected = False

                # Reconnect with exponential backoff
                if self.running and self.should_reconnect:
                    logger.info(f"Reconnecting in {self.reconnect_delay} seconds...")
                    time.sleep(self.reconnect_delay)

                    # Increase delay for next time, with some randomness
                    self.reconnect_delay = min(
                        self.max_reconnect_delay,
                        self.reconnect_delay * (1.5 + 0.5 * random.random())
                    )

            except Exception as e:
                self.connected = False
                self.stats['connection_failures'] += 1
                self.stats['last_error'] = str(e)
                logger.error(f"WebSocket error: {e}")

                # Reconnect after delay
                if self.running and self.should_reconnect:
                    logger.info(f"Connection failed, reconnecting in {self.reconnect_delay} seconds...")
                    time.sleep(self.reconnect_delay)

                    # Increase delay for next time
                    self.reconnect_delay = min(self.max_reconnect_delay, self.reconnect_delay * 1.5)

        logger.info("WebSocket client thread exiting")

    def _start_processor(self) -> None:
        """Start the message processor thread."""
        self.processor = threading.Thread(
            target=self._process_messages,
            daemon=True,
            name="ws-processor"
        )
        self.processor.start()
        logger.debug("Message processor thread started")

    def _start_health_checker(self) -> None:
        """Start the connection health checker thread."""
        self.health_checker = threading.Thread(
            target=self._check_connection_health,
            daemon=True,
            name="ws-health-checker"
        )
        self.health_checker.start()
        logger.debug("Health checker thread started")

    def _on_open(self, ws):
        """
        Handle WebSocket open event.

        Args:
            ws: WebSocket instance
        """
        self.connected = True
        self.stats['successful_connections'] += 1
        self.last_message_time = time.time()  # Reset health timer

        # Reset reconnect delay on successful connection
        self.reconnect_delay = 2

        logger.info(f"Connected to WebSocket: {self.url}")

        # Optional - send authentication or subscription request here if needed
        # self._send_authentication()

    def _on_message(self, ws, message):
        """
        Handle WebSocket message event.
        Queues messages for processing to avoid blocking the WebSocket thread.

        Args:
            ws: WebSocket instance
            message: Message received from the server
        """
        self.stats['messages_received'] += 1
        self.last_message_time = time.time()  # Update last message time for health check

        # Add to queue for processing, with a timeout to avoid blocking
        try:
            self.message_queue.put(message, timeout=1)
        except queue.Full:
            # Queue is full, log warning and discard message
            logger.warning("Message queue full, discarding message")

    def _on_error(self, ws, error):
        """
        Handle WebSocket error event.

        Args:
            ws: WebSocket instance
            error: Error that occurred
        """
        self.stats['last_error'] = str(error) if error else "Unknown error"
        logger.error(f"WebSocket error: {error}")

    def _on_close(self, ws, close_status_code, close_msg):
        """
        Handle WebSocket close event.

        Args:
            ws: WebSocket instance
            close_status_code: Status code of the close
            close_msg: Close message
        """
        self.connected = False
        logger.info(f"WebSocket closed: {close_status_code} {close_msg}")

    def _process_messages(self) -> None:
        """
        Process messages from the queue.
        Runs in a separate thread to avoid blocking the WebSocket thread.
        """
        logger.debug("Message processor started")

        while self.running:
            try:
                # Get message from queue with timeout to allow for thread termination
                try:
                    message = self.message_queue.get(timeout=1)
                except queue.Empty:
                    # No message available, continue loop
                    continue

                # Process the message
                start_time = time.time()

                try:
                    self._handle_message(message)
                    self.stats['messages_processed'] += 1
                except Exception as e:
                    logger.error(f"Error processing message: {e}")

                # Update processing time statistic
                process_time = time.time() - start_time
                self.stats['process_time'] = process_time

                # Signal task completion
                self.message_queue.task_done()

            except Exception as e:
                logger.error(f"Unexpected error in message processor: {e}")
                time.sleep(1)  # Prevent tight loop in case of persistent errors

        logger.debug("Message processor stopped")

    def _handle_message(self, message: str) -> None:
        """
        Parse and handle a WebSocket message.

        Args:
            message: Message received from the server
        """
        try:
            data = json.loads(message)

            # Check for sensor updates
            if data.get("type") == "sensors-update":
                sensors = data.get("sensors", [])
                if sensors:
                    logger.info(f"Received {len(sensors)} sensors via WebSocket")
                    self.renderer.update_sensors(sensors)
                else:
                    logger.warning("Received empty sensors list")
            elif data.get("type") == "ping":
                # Handle ping messages - could send pong if needed
                logger.debug("Received ping message")
            else:
                # Log other message types
                logger.debug(f"Received message of type: {data.get('type', 'unknown')}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in WebSocket message: {e}. Raw message: {message[:100]}...")
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e