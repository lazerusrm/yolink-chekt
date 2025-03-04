#!/usr/bin/env python3
"""
Main entry point for the YoLink Dashboard RTSP Server.
"""
import os
import sys
import signal
import logging
import threading
import time
from typing import Dict, Any

from flask import Flask

# Import application modules
from .config import get_config
from .renderer import DashboardRenderer
from .websocket_client import WebSocketClient
from .rtsp_streamer import RtspStreamer
from .onvif_service import OnvifService
from .routes import create_api_routes
from .onvif import create_onvif_routes
from .multi_profile_rtsp_streamer import MultiProfileRtspStreamer
from .onvif_integration import setup_integration, OnvifStreamingIntegration

# Configure logging
logger = logging.getLogger(__name__)


class DashboardApp:
    """
    Main application class for the YoLink Dashboard RTSP Server.
    """

    def __init__(self):
        """
        Initialize the application.
        """
        # Load configuration
        self.config = get_config()

        # Create Flask app
        self.app = Flask(__name__)

        # Create components
        self.renderer = DashboardRenderer(self.config)
        self.streamer = RtspStreamer(self.config, self.renderer)

        # Initialize services
        self.ws_client = None
        self.onvif_service = None

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

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

    def _cycle_pages(self):
        """
        Automatic page cycling thread function with proper shutdown support.
        """
        self.running = True  # Flag controlled by stop() method

        while self.running:
            try:
                if self.renderer.total_pages > 1:
                    next_page = (self.renderer.current_page + 1) % self.renderer.total_pages
                    self.renderer.set_page(next_page)
                    logger.debug(f"Cycled to page {next_page + 1}/{self.renderer.total_pages}")
            except Exception as e:
                logger.error(f"Error during page cycling: {e}")

            # Use small sleep intervals so we can check self.running frequently
            # This helps with quick shutdown
            cycle_interval = self.config.get("cycle_interval", 10000) / 1000.0  # Convert to seconds

            # Sleep in small chunks to check running flag more frequently
            chunk_size = 0.5  # seconds
            chunks = int(cycle_interval / chunk_size)

            for _ in range(chunks):
                if not self.running:
                    break
                time.sleep(chunk_size)

            # Handle any remaining time
            remaining_time = cycle_interval - (chunks * chunk_size)
            if remaining_time > 0 and self.running:
                time.sleep(remaining_time)

    def start(self):
        """
        Start the YoLink Dashboard RTSP Server with multi-resolution support.
        """
        logger.info("Starting YoLink Dashboard RTSP Server")

        try:
            # Setup WebSocket client
            ws_url = f"ws://{self.config['dashboard_url'].replace('http://', '').replace('https://', '')}/ws"
            self.ws_client = WebSocketClient(ws_url, self.renderer)
            self.ws_client.start()
            logger.info(f"WebSocket client connected to {ws_url}")
        except Exception as e:
            logger.error(f"Failed to start WebSocket client: {e}")
            # Continue operation even if WebSocket fails - we'll show empty data

        try:
            # Initialize the appropriate streamer based on configuration
            use_multi_profile = (self.config.get("enable_low_res_profile", False) or
                                 self.config.get("enable_mobile_profile", False))

            if use_multi_profile:
                logger.info("Using multi-profile RTSP streamer")
                self.streamer = MultiProfileRtspStreamer(self.config, self.renderer)
            else:
                # Start standard RTSP streamer
                self.streamer = RtspStreamer(self.config, self.renderer)

            # Start RTSP streamer
            self.streamer.start()
            logger.info(
                f"RTSP streamer started on port {self.config.get('rtsp_port')} with stream name '{self.config.get('stream_name')}'")
        except Exception as e:
            logger.error(f"Failed to start RTSP streamer: {e}")
            # This is critical, but we'll continue to at least provide API access

        # Start ONVIF service if enabled
        if self.config.get("enable_onvif"):
            try:
                # Configure ONVIF authentication credentials if provided
                if "onvif_username" not in self.config:
                    self.config["onvif_username"] = "admin"
                if "onvif_password" not in self.config:
                    self.config["onvif_password"] = "123456"

                self.onvif_service = OnvifService(self.config)

                # Update media profiles if we're using multi-profile
                if use_multi_profile and hasattr(self.onvif_service, 'update_media_profiles'):
                    self.onvif_service.update_media_profiles(self.config)

                self.onvif_service.start()

                # Set up integration between ONVIF and streamer if using multi-profile
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
                    masked_password = self.config["onvif_password"][:1] + masked_password + self.config[
                                                                                                "onvif_password"][-1:]

                logger.info(
                    f"ONVIF service started on port {self.config.get('onvif_port')} with credentials: {self.config['onvif_username']}/{masked_password}")
                logger.info(
                    f"ONVIF authentication method: {self.config.get('onvif_auth_method', 'both')}, required: {self.config.get('onvif_auth_required', True)}")
            except Exception as e:
                logger.error(f"Failed to start ONVIF service: {e}")
                self.config["enable_onvif"] = False
                # Continue without ONVIF

        try:
            # Start page cycling thread
            self.page_cycling_thread = threading.Thread(target=self._cycle_pages, daemon=True)
            self.page_cycling_thread.start()
            logger.info(f"Page cycling started with interval {self.config.get('cycle_interval')}ms")
        except Exception as e:
            logger.error(f"Failed to start page cycling: {e}")
            # Continue without page cycling

        try:
            # Configure API routes
            create_api_routes(self.app, self.config, self.renderer, self.streamer)

            # Configure ONVIF routes with a reference to the ONVIF service and renderer for authentication and snapshots
            create_onvif_routes(
                self.app,
                self.config,
                onvif_service=self.onvif_service if self.config.get("enable_onvif") else None,
                renderer=self.renderer  # Pass the renderer to enable snapshot functionality
            )

            # Start Flask server
            logger.info(f"Starting HTTP server on port {self.config.get('http_port')}")
            self.app.run(host="0.0.0.0", port=self.config.get("http_port"))
        except Exception as e:
            logger.critical(f"Failed to start HTTP server: {e}")
            self.stop()  # Clean shutdown
            raise  # Re-raise to exit the application

    def stop(self):
        """
        Stop the YoLink Dashboard RTSP Server with improved cleanup.
        """
        logger.info("Stopping YoLink Dashboard RTSP Server")

        # Set global running flag to false to stop any daemon threads
        self.running = False

        # Stop services in reverse order of startup
        if hasattr(self, 'onvif_service') and self.onvif_service:
            try:
                self.onvif_service.stop()
                logger.info("ONVIF service stopped")
            except Exception as e:
                logger.error(f"Error stopping ONVIF service: {e}")

        if hasattr(self, 'streamer') and self.streamer:
            try:
                self.streamer.stop()
                logger.info("RTSP streamer stopped")
            except Exception as e:
                logger.error(f"Error stopping RTSP streamer: {e}")

        if hasattr(self, 'ws_client') and self.ws_client:
            try:
                self.ws_client.close()
                logger.info("WebSocket client stopped")
            except Exception as e:
                logger.error(f"Error stopping WebSocket client: {e}")

        logger.info("All services stopped")


def main():
    """
    Main entry point function.
    """
    try:
        app = DashboardApp()
        app.start()
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()