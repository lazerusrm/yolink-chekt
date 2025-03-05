#!/usr/bin/env python3
"""
Main entry point for the YoLink Dashboard RTSP Server.
Optimized for resource efficiency and robust operation.
"""
import os
import sys
import signal
import logging
import threading
import time
import gc
import atexit
import traceback
import resource
from typing import Dict, Any, List, Optional, Set
import concurrent.futures

from flask import Flask

# Import application modules
from config import get_config
from renderer import DashboardRenderer
from websocket_client import WebSocketClient
from multi_profile_rtsp_streamer import MultiProfileRtspStreamer
from onvif_service import OnvifService
from routes import create_api_routes
from onvif import create_onvif_routes
from onvif_integration import setup_integration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s',
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


class ResourceMonitor(threading.Thread):
    """A thread that monitors system resource usage."""

    def __init__(self, app, check_interval=30):
        """
        Initialize the resource monitor.

        Args:
            app: Reference to the application
            check_interval: How often to check resource usage (seconds)
        """
        super().__init__(daemon=True)
        self.app = app
        self.check_interval = check_interval
        self.running = True

    def run(self):
        """Main monitoring loop."""
        logger.info("Resource monitor started")

        # Initial resource snapshot
        last_usage = self._get_resource_usage()
        start_time = time.time()

        while self.running:
            time.sleep(self.check_interval)

            try:
                # Get current resource usage
                current_usage = self._get_resource_usage()

                # Log resource usage
                runtime = time.time() - start_time
                logger.info(
                    f"Resource usage after {runtime:.1f}s: "
                    f"CPU {current_usage['cpu_percent']:.1f}%, "
                    f"Memory {current_usage['memory_mb']:.1f}MB, "
                    f"Threads: {current_usage['thread_count']}"
                )

                # Check for memory leaks
                memory_increase = current_usage['memory_mb'] - last_usage['memory_mb']
                if memory_increase > 100:  # Over 100MB increase
                    logger.warning(
                        f"Potential memory leak detected: {memory_increase:.1f}MB increase "
                        f"in the last {self.check_interval} seconds"
                    )

                # Check for thread leaks
                thread_increase = current_usage['thread_count'] - last_usage['thread_count']
                if thread_increase > 5:  # More than 5 new threads
                    logger.warning(
                        f"Potential thread leak detected: {thread_increase} new threads "
                        f"in the last {self.check_interval} seconds"
                    )

                # Update last usage
                last_usage = current_usage

                # Trigger garbage collection if memory usage is high
                if current_usage['memory_mb'] > 1000:  # Over 1GB
                    logger.info("High memory usage detected, triggering garbage collection")
                    gc.collect()

            except Exception as e:
                logger.error(f"Error in resource monitor: {e}")

        logger.info("Resource monitor stopped")

    def _get_resource_usage(self):
        """Get current system resource usage."""
        try:
            import psutil
            process = psutil.Process(os.getpid())

            # Get memory info
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)  # Convert to MB

            # Get CPU usage
            cpu_percent = process.cpu_percent(interval=0.1)

            # Get thread count
            thread_count = process.num_threads()

            # Get open file count
            try:
                open_files = len(process.open_files())
            except Exception:
                open_files = 0

            return {
                "memory_mb": memory_mb,
                "cpu_percent": cpu_percent,
                "thread_count": thread_count,
                "open_files": open_files
            }

        except ImportError:
            # Fallback if psutil is not available
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            memory_mb = rusage.ru_maxrss / 1024  # Convert to MB
            thread_count = threading.active_count()

            return {
                "memory_mb": memory_mb,
                "cpu_percent": 0,  # Not available without psutil
                "thread_count": thread_count,
                "open_files": 0
            }

    def stop(self):
        """Stop the monitor."""
        self.running = False


class DashboardApp:
    """
    Main application class for the YoLink Dashboard RTSP Server.
    Manages lifecycle of all components.
    """

    def __init__(self):
        """
        Initialize the application.
        """
        # Load configuration
        self.config = get_config()

        # Configure logging level from config
        log_level = self.config.get("log_level", "INFO").upper()
        numeric_level = getattr(logging, log_level, logging.INFO)
        logging.getLogger().setLevel(numeric_level)
        logger.info(f"Log level set to {log_level}")

        # Initialize Flask app with production settings
        self.app = Flask(__name__)

        # Application components - initialized in start()
        self.renderer = None
        self.streamer = None
        self.ws_client = None
        self.onvif_service = None
        self.onvif_integration = None
        self.http_server = None
        self.resource_monitor = None

        # Thread pool for background tasks
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=5,
            thread_name_prefix="app-worker"
        )

        # Lifecycle flags
        self.running = False
        self.page_cycling_thread = None

        # Setup signal handlers
        self._setup_signal_handlers()

        # Register exit handler
        atexit.register(self.stop)

    def _setup_signal_handlers(self):
        """Set up handlers for OS signals."""
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        # Handle HUP for config reload if available
        try:
            signal.signal(signal.SIGHUP, self._handle_config_reload)
        except AttributeError:
            # SIGHUP not available on Windows
            pass

    def _handle_shutdown(self, signum, frame):
        """
        Handle shutdown signals.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)

    def _handle_config_reload(self, signum, frame):
        """
        Handle SIGHUP signal to reload configuration.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        logger.info("Received SIGHUP, reloading configuration...")
        try:
            new_config = get_config()
            self.config.update(new_config)
            logger.info("Configuration reloaded")
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")

    def _cycle_pages(self):
        """
        Automatic page cycling thread function with proper shutdown support.
        """
        self.page_cycling_running = True

        logger.info("Page cycling thread started")
        while self.page_cycling_running and self.running:
            try:
                if self.renderer.total_pages > 1:
                    next_page = (self.renderer.current_page + 1) % self.renderer.total_pages
                    self.renderer.set_page(next_page)
                    logger.debug(f"Cycled to page {next_page + 1}/{self.renderer.total_pages}")
            except Exception as e:
                logger.error(f"Error during page cycling: {e}")

            # Use small sleep intervals for more responsive shutdown
            cycle_interval = self.config.get("cycle_interval", 10000) / 1000.0  # Convert to seconds
            chunk_size = 0.5  # seconds
            chunks = int(cycle_interval / chunk_size)

            for _ in range(chunks):
                if not self.page_cycling_running or not self.running:
                    break
                time.sleep(chunk_size)

            # Handle any remaining time
            remaining_time = cycle_interval - (chunks * chunk_size)
            if remaining_time > 0 and self.page_cycling_running and self.running:
                time.sleep(remaining_time)

        logger.info("Page cycling thread stopped")

    def start(self):
        """
        Start the YoLink Dashboard RTSP Server with multi-resolution support.
        Initializes and starts all components in the proper order.
        """
        logger.info("Starting YoLink Dashboard RTSP Server")
        self.running = True

        try:
            # Initialize the renderer first since other components depend on it
            self.renderer = DashboardRenderer(self.config)
            logger.info(f"Dashboard renderer initialized at {self.config.get('width')}x{self.config.get('height')}")

            # Start resource monitor
            if self.config.get("enable_resource_monitoring", True):
                self.resource_monitor = ResourceMonitor(self)
                self.resource_monitor.start()
                logger.info("Resource monitoring enabled")

            # Connect to WebSocket data source
            ws_connected = self._start_websocket_client()
            if not ws_connected:
                # Continue operation even if WebSocket fails - we'll show empty data
                logger.warning("Operating without WebSocket connection")

            # Start RTSP streamer
            streaming_started = self._start_streaming()
            if not streaming_started:
                # This is a critical service - report error but continue to at least provide APIs
                logger.error("Failed to start streaming, continuing with limited functionality")

            # Start ONVIF service if enabled
            if self.config.get("enable_onvif"):
                onvif_started = self._start_onvif_service()
                if not onvif_started:
                    logger.warning("ONVIF service failed to start, continuing without ONVIF support")
                    self.config["enable_onvif"] = False
            else:
                logger.info("ONVIF service is disabled in configuration")

            # Start page cycling thread
            self._start_page_cycling()

            # Configure API routes
            self._setup_api_routes()

            # Start Flask server
            self._start_http_server()

        except Exception as e:
            logger.critical(f"Failed to start server: {e}")
            logger.debug(f"Exception details: {traceback.format_exc()}")
            self.stop()  # Clean shutdown
            raise  # Re-raise to exit the application

    def _start_websocket_client(self) -> bool:
        """
        Initialize and start the WebSocket client.

        Returns:
            bool: True if successfully connected, False otherwise
        """
        try:
            # Setup WebSocket client
            ws_url = f"ws://{self.config['dashboard_url'].replace('http://', '').replace('https://', '')}/ws"
            self.ws_client = WebSocketClient(ws_url, self.renderer)
            self.ws_client.start()
            logger.info(f"WebSocket client connected to {ws_url}")
            return True
        except Exception as e:
            logger.error(f"Failed to start WebSocket client: {e}")
            return False

    def _start_streaming(self) -> bool:
        """
        Initialize and start the RTSP streaming service.

        Returns:
            bool: True if successfully started, False otherwise
        """
        try:
            # Initialize the multi-profile streamer
            self.streamer = MultiProfileRtspStreamer(self.config, self.renderer)

            # Start RTSP streamer
            self.streamer.start()
            logger.info(
                f"RTSP streamer started on port {self.config.get('rtsp_port')} with stream name '{self.config.get('stream_name')}'")
            return True
        except Exception as e:
            logger.error(f"Failed to start RTSP streamer: {e}")
            return False

    def _start_onvif_service(self) -> bool:
        """
        Initialize and start the ONVIF service.

        Returns:
            bool: True if successfully started, False otherwise
        """
        try:
            # Configure ONVIF authentication credentials if not provided
            if "onvif_username" not in self.config:
                self.config["onvif_username"] = "admin"
            if "onvif_password" not in self.config:
                self.config["onvif_password"] = "123456"

            # Start ONVIF service
            self.onvif_service = OnvifService(self.config)

            # Update media profiles for multi-profile support
            if hasattr(self.onvif_service, 'update_media_profiles'):
                self.onvif_service.update_media_profiles(self.config)

            # Start the service
            self.onvif_service.start()

            # Set up integration between ONVIF and streamer if using multi-profile
            use_multi_profile = (self.config.get("enable_low_res_profile", False) or
                                 self.config.get("enable_mobile_profile", False))

            if use_multi_profile:
                self.onvif_integration = setup_integration(
                    self.config,
                    self.onvif_service,
                    self.streamer,
                    self.renderer
                )

            # Log authentication details (masking password)
            masked_password = "*" * (len(self.config["onvif_password"]) - 2)
            if len(self.config["onvif_password"]) > 2:
                masked_password = self.config["onvif_password"][:1] + masked_password + self.config["onvif_password"][
                                                                                        -1:]

            logger.info(
                f"ONVIF service started on port {self.config.get('onvif_port')} with credentials: {self.config['onvif_username']}/{masked_password}")
            return True
        except Exception as e:
            logger.error(f"Failed to start ONVIF service: {e}")
            return False

    def _start_page_cycling(self) -> None:
        """Start the page cycling thread."""
        try:
            # Start page cycling thread
            self.page_cycling_thread = threading.Thread(
                target=self._cycle_pages,
                daemon=True,
                name="page-cycling"
            )
            self.page_cycling_thread.start()
            logger.info(f"Page cycling started with interval {self.config.get('cycle_interval')}ms")
        except Exception as e:
            logger.error(f"Failed to start page cycling: {e}")
            # Continue without page cycling

    def _setup_api_routes(self) -> None:
        """Configure API routes for the Flask application."""
        try:
            # Configure API routes
            create_api_routes(self.app, self.config, self.renderer, self.streamer)

            # Configure ONVIF routes if enabled
            if self.config.get("enable_onvif"):
                create_onvif_routes(
                    self.app,
                    self.config,
                    onvif_service=self.onvif_service,
                    renderer=self.renderer
                )

            logger.info("API routes configured")
        except Exception as e:
            logger.error(f"Failed to configure API routes: {e}")
            raise

    def _start_http_server(self) -> None:
        """Start the Flask HTTP server."""
        try:
            # Start Flask server
            http_port = self.config.get("http_port", 3001)
            logger.info(f"Starting HTTP server on port {http_port}")

            # Use threading server for better performance
            self.app.run(
                host="0.0.0.0",
                port=http_port,
                threaded=True,
                debug=False,  # Disable debug mode for production
                use_reloader=False  # Disable reloader to prevent duplicate processes
            )
        except Exception as e:
            logger.error(f"Failed to start HTTP server: {e}")
            raise

    def stop(self) -> None:
        """
        Stop the YoLink Dashboard RTSP Server with improved cleanup.
        Stops all components in the proper order.
        """
        # Avoid multiple stops
        if not self.running:
            return

        logger.info("Stopping YoLink Dashboard RTSP Server")
        self.running = False

        # Stop services in reverse order of startup
        self._stop_page_cycling()
        self._stop_onvif()
        self._stop_streamer()
        self._stop_websocket()
        self._stop_resource_monitor()

        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)

        # Final cleanup
        logger.info("All services stopped")
        gc.collect()

    def _stop_page_cycling(self) -> None:
        """Stop the page cycling thread."""
        if hasattr(self, 'page_cycling_thread') and self.page_cycling_thread:
            try:
                self.page_cycling_running = False
                # No need to join daemon thread
                logger.info("Page cycling stopped")
            except Exception as e:
                logger.error(f"Error stopping page cycling: {e}")

    def _stop_onvif(self) -> None:
        """Stop the ONVIF service."""
        if hasattr(self, 'onvif_service') and self.onvif_service:
            try:
                self.onvif_service.stop()
                logger.info("ONVIF service stopped")
            except Exception as e:
                logger.error(f"Error stopping ONVIF service: {e}")

    def _stop_streamer(self) -> None:
        """Stop the RTSP streamer."""
        if hasattr(self, 'streamer') and self.streamer:
            try:
                self.streamer.stop()
                logger.info("RTSP streamer stopped")
            except Exception as e:
                logger.error(f"Error stopping RTSP streamer: {e}")

    def _stop_websocket(self) -> None:
        """Stop the WebSocket client."""
        if hasattr(self, 'ws_client') and self.ws_client:
            try:
                self.ws_client.close()
                logger.info("WebSocket client stopped")
            except Exception as e:
                logger.error(f"Error stopping WebSocket client: {e}")

    def _stop_resource_monitor(self) -> None:
        """Stop the resource monitor."""
        if hasattr(self, 'resource_monitor') and self.resource_monitor:
            try:
                self.resource_monitor.stop()
                logger.info("Resource monitor stopped")
            except Exception as e:
                logger.error(f"Error stopping resource monitor: {e}")


def main():
    """
    Main entry point function.
    """
    try:
        # Set process name if running on Linux
        try:
            import setproctitle
            setproctitle.setproctitle("yolink-dashboard")
        except ImportError:
            pass

        # Increase resource limits
        try:
            # Increase file descriptor limit
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(4096, hard), hard))

            # Log available resources
            new_soft, new_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            logger.info(f"File descriptor limit: {new_soft}/{new_hard}")
        except Exception as e:
            logger.warning(f"Could not adjust resource limits: {e}")

        # Start the application
        app = DashboardApp()
        app.start()
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()