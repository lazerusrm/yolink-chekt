"""
API routes for the YoLink Dashboard RTSP Server.
"""
import os
import time
import io
import datetime
import logging
from typing import Dict, Any, List, Tuple

from flask import Flask, request, jsonify, Response

logger = logging.getLogger(__name__)


def create_api_routes(app: Flask, config: Dict[str, Any],
                      renderer, streamer) -> None:
    """
    Configure API routes for the YoLink Dashboard RTSP Server.

    Args:
        app: Flask application
        config: Application configuration
        renderer: DashboardRenderer instance
        streamer: RTSPStreamer instance
    """

    @app.route('/')
    def index():
        """
        Root endpoint providing basic status information.
        """
        return "YoLink RTSP Streamer with ONVIF is running!"

    @app.route('/status')
    def status():
        """
        Get detailed status of the YoLink Dashboard RTSP Server.
        """
        # Build RTSP stream URL
        stream_url = f"rtsp://{config['server_ip']}:{config['rtsp_port']}/{config['stream_name']}"

        # Build ONVIF URL if enabled
        onvif_url = None
        if config.get("enable_onvif"):
            onvif_url = f"onvif://{config['server_ip']}:{config['onvif_port']}"

        # Count active sensors (those seen within a day)
        active_sensors = len([s for s in renderer.sensor_data if "2025" in s.get("last_seen", "")])

        # Build response object
        return jsonify({
            "status": "online",
            "sensors": {
                "total": len(renderer.sensor_data),
                "alarmsActive": len(renderer.alarm_sensors),
                "activeSensors": active_sensors
            },
            "stream": {
                "rtspUrl": stream_url,
                "onvifUrl": onvif_url,
                "frameRate": config.get("frame_rate"),
                "resolution": f"{config.get('width')}x{config.get('height')}",
                "currentPage": renderer.current_page + 1,
                "totalPages": renderer.total_pages,
            },
            "system": {
                "uptime": time.time() - os.getpid(),
                "memory": {}
            },
            "lastUpdate": datetime.datetime.now().isoformat()
        })

    @app.route('/snapshot')
    def snapshot():
        """
        Generate and return a snapshot image of the current dashboard view.
        """
        try:
            # Render current frame
            frame = renderer.render_frame(config['width'], config['height'])

            # Convert to JPEG
            buf = io.BytesIO()
            frame.save(buf, format="JPEG", quality=75)

            # Return as image response
            return Response(buf.getvalue(), mimetype="image/jpeg")
        except Exception as e:
            logger.error(f"Snapshot error: {e}")
            return "Failed to generate snapshot", 500

    @app.route('/restart-stream', methods=["POST"])
    def restart_stream():
        """
        Restart the RTSP stream.
        """
        try:
            streamer.restart_stream()
            return jsonify({
                "success": True,
                "message": "Stream restart initiated",
                "timestamp": datetime.datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Restart stream error: {e}")
            return jsonify({
                "success": False,
                "message": "Failed to restart stream",
                "error": str(e)
            }), 500

    @app.route('/sensors')
    def sensors():
        """
        Get information about all sensors.
        """
        sensors_list = []
        for s in renderer.sensor_data:
            sensors_list.append({
                "name": s.get("name"),
                "type": s.get("type"),
                "state": s.get("state"),
                "battery": s.get("battery"),
                "signal": s.get("signal"),
                "last_seen": s.get("last_seen"),
                "temperature": s.get("temperature"),
                "humidity": s.get("humidity")
            })
        return jsonify({
            "count": len(sensors_list),
            "sensors": sensors_list
        })

    @app.route('/page/<int:page_num>', methods=["POST"])
    def set_page(page_num):
        """
        Set the current page of the sensor display.

        Args:
            page_num: Page number (1-based)
        """
        # Convert to 0-based index
        page_num -= 1

        # Validate page number
        if page_num < 0 or page_num >= renderer.total_pages:
            return jsonify({
                "error": "Invalid page number",
                "valid_range": f"1-{renderer.total_pages}"
            }), 400

        # Set page and return success
        renderer.set_page(page_num)
        return jsonify({
            "success": True,
            "current_page": page_num + 1,
            "totalPages": renderer.total_pages
        })

    logger.info("API routes configured")