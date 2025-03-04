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
from app.config import get_config
from app.dashboard.renderer import DashboardRenderer
from app.services.websocket_client import WebSocketClient
from app.services.rtsp_streamer import RtspStreamer
from app.services.onvif_service import OnvifService
from app.api.routes import create_api_routes
from app.api.onvif import create_onvif_routes

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
        Automatic page cycling thread function.
        """
        while True:
            if self.renderer.total_pages > 1:
                next_page = (self.renderer.current_page + 1) % self.renderer.total_pages
                self.renderer.set_page(next_page)
            time.sleep(self.config.get("cycle_interval") / 1000.0)

    def start(self):
        """
        Start the YoLink Dashboard RTSP Server.
        """
        logger.info("Starting YoLink Dashboard RTSP Server")

        # Setup WebSocket client
        ws_url = f"ws://{self.config['dashboard_url'].replace('http://', '').replace('https://', '')}/ws"
        self.ws_client = WebSocketClient(ws_url, self.renderer)
        self.ws_client.start()
        logger.info(f"WebSocket client connected to {ws_url}")

        # Start RTSP streamer
        self.streamer.start()
        logger.info("RTSP streamer started")

        # Start ONVIF service if enabled
        if self.config.get("enable_onvif"):
            self.onvif_service = OnvifService(self.config)
            self.onvif_service.start()
            logger.info("ONVIF service started")

        # Start page cycling thread
        threading.Thread(target=self._cycle_pages, daemon=True).start()
        logger.info(f"Page cycling started with interval {self.config.get('cycle_interval')}ms")

        # Configure API routes
        create_api_routes(self.app, self.config, self.renderer, self.streamer)
        create_onvif_routes(self.app, self.config)

        # Start Flask server
        logger.info(f"Starting HTTP server on port {self.config.get('http_port')}")
        self.app.run(host="0.0.0.0", port=self.config.get("http_port"))

    def stop(self):
        """
        Stop the YoLink Dashboard RTSP Server.
        """
        logger.info("Stopping YoLink Dashboard RTSP Server")

        # Stop services
        if self.streamer:
            self.streamer.stop()

        if self.onvif_service:
            self.onvif_service.stop()

        if self.ws_client:
            self.ws_client.close()

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