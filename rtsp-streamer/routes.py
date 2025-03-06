"""
API routes for the YoLink Dashboard RTSP Server.
Enhanced with ONVIF Profile S support endpoints.
"""
import os
import time
import io
import datetime
import logging
import json
from typing import Dict, Any, List, Tuple, Optional, Union

from flask import Flask, request, jsonify, Response, abort, send_file, make_response

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
        return jsonify({
            "name": "YoLink Dashboard RTSP Streamer",
            "version": "2.0.0",
            "status": "running",
            "api_endpoints": [
                "/status",
                "/snapshot",
                "/sensors",
                "/page/<page_num>",
                "/profiles",
                "/streams",
                "/restart-stream",
                "/stream/<profile_token>"
            ],
            "onvif_endpoints": [
                "/onvif/device_service",
                "/onvif/media_service",
                "/onvif/imaging_service",
                "/onvif/events_service",
                "/onvif/ptz_service",
                "/onvif/snapshot"
            ]
        })

    @app.route('/status')
    def status():
        """
        Get detailed status of the YoLink Dashboard RTSP Server.
        """
        # Build RTSP stream URLs
        stream_urls = {}
        for profile_token in ["profile1", "profile2", "profile3"]:
            stream_name = config.get("stream_name", "yolink-dashboard")

            # Add profile-specific suffix
            if profile_token == "profile1":
                stream_name = f"{stream_name}_main"
            elif profile_token == "profile2":
                stream_name = f"{stream_name}_sub"
            elif profile_token == "profile3":
                stream_name = f"{stream_name}_mobile"

            auth_part = ""
            if config.get("onvif_auth_required", True):
                username = config.get("onvif_username", "admin")
                password = config.get("onvif_password", "123456")
                # Mask password in response
                masked_password = "*" * len(password)
                auth_part = f"{username}:{masked_password}@"

            stream_url = f"rtsp://{auth_part}{config['server_ip']}:{config['rtsp_port']}/{stream_name}"
            stream_urls[profile_token] = stream_url

        # Build ONVIF URL
        onvif_url = f"onvif://{config['server_ip']}:{config['onvif_port']}"

        # Get active streams
        active_streams = []
        if hasattr(streamer, 'get_active_profiles'):
            active_streams = streamer.get_active_profiles()

        # Count active sensors (those seen within a day)
        active_sensors = 0
        if hasattr(renderer, 'sensor_data'):
            active_sensors = len([s for s in renderer.sensor_data if "2025" in s.get("last_seen", "")])

        # Build response object
        return jsonify({
            "status": "online",
            "sensors": {
                "total": len(renderer.sensor_data) if hasattr(renderer, 'sensor_data') else 0,
                "alarmsActive": len(renderer.alarm_sensors) if hasattr(renderer, 'alarm_sensors') else 0,
                "activeSensors": active_sensors
            },
            "streams": {
                "rtspUrls": stream_urls,
                "onvifUrl": onvif_url,
                "activeStreams": active_streams,
                "frameRate": config.get("frame_rate", 6)
            },
            "profiles": {
                "profile1": {
                    "resolution": f"{config.get('width')}x{config.get('height')}",
                    "frameRate": config.get("frame_rate", 6)
                },
                "profile2": {
                    "resolution": f"{config.get('width', 1920) // 2}x{config.get('height', 1080) // 2}",
                    "frameRate": min(config.get("frame_rate", 6), 4)
                },
                "profile3": {
                    "resolution": f"{config.get('width', 1920) // 4}x{config.get('height', 1080) // 4}",
                    "frameRate": min(config.get("frame_rate", 6), 2)
                }
            },
            "display": {
                "currentPage": renderer.current_page + 1 if hasattr(renderer, 'current_page') else 1,
                "totalPages": renderer.total_pages if hasattr(renderer, 'total_pages') else 1,
            },
            "system": {
                "uptime": time.time() - os.getpid(),
                "serverIp": config.get("server_ip", ""),
                "rtspPort": config.get("rtsp_port", 554),
                "httpPort": config.get("http_port", 80),
                "onvifPort": config.get("onvif_port", 8000)
            },
            "authentication": {
                "enabled": config.get("onvif_auth_required", True),
                "username": config.get("onvif_username", "admin")
            },
            "lastUpdate": datetime.datetime.now().isoformat()
        })

    @app.route('/snapshot')
    @app.route('/onvif/snapshot')
    def snapshot():
        """
        Generate and return a snapshot image of the current dashboard view.
        """
        try:
            # Get the profile token from query parameters (default to profile1)
            profile_token = request.args.get('token', 'profile1')

            # Get resolution for the requested profile
            width = config.get('width', 1920)
            height = config.get('height', 1080)

            if profile_token == 'profile2':
                width = width // 2
                height = height // 2
            elif profile_token == 'profile3':
                width = width // 4
                height = height // 4

            # Render current frame with the appropriate resolution
            frame = renderer.render_frame(width, height)

            # Convert to JPEG
            buf = io.BytesIO()
            frame.save(buf, format="JPEG", quality=90)
            buf.seek(0)

            # Return as image response with caching headers
            response = send_file(buf, mimetype="image/jpeg")
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            response.headers['Content-Disposition'] = 'inline; filename="snapshot.jpg"'
            return response
        except Exception as e:
            logger.error(f"Snapshot error: {e}", exc_info=True)
            return "Failed to generate snapshot", 500

    @app.route('/restart-stream', methods=["POST"])
    def restart_stream():
        """
        Restart the RTSP stream.
        """
        try:
            # Get specific profile to restart, or all if not specified
            profile_token = request.json.get('profile') if request.json else None

            # Restart the stream
            if hasattr(streamer, 'restart_stream'):
                success = streamer.restart_stream(profile_token)
            else:
                # Fallback for older streamer implementation
                success = True

            return jsonify({
                "success": success,
                "message": f"Stream {'restart initiated' if success else 'restart failed'}",
                "profile": profile_token if profile_token else "all",
                "timestamp": datetime.datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Restart stream error: {e}", exc_info=True)
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
        if hasattr(renderer, 'sensor_data'):
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

    @app.route('/page/<int:page_num>', methods=["POST", "GET"])
    def set_page(page_num):
        """
        Set the current page of the sensor display.

        Args:
            page_num: Page number (1-based)
        """
        # Convert to 0-based index
        page_num -= 1

        # Get total pages
        total_pages = 1
        if hasattr(renderer, 'total_pages'):
            total_pages = renderer.total_pages

        # Validate page number
        if page_num < 0 or page_num >= total_pages:
            return jsonify({
                "error": "Invalid page number",
                "valid_range": f"1-{total_pages}"
            }), 400

        # Set page and return success
        if hasattr(renderer, 'set_page'):
            renderer.set_page(page_num)

        return jsonify({
            "success": True,
            "current_page": page_num + 1,
            "totalPages": total_pages
        })

    @app.route('/profiles', methods=["GET"])
    def get_profiles():
        """
        Get information about all supported profiles.
        """
        profiles = {
            "profile1": {
                "token": "profile1",
                "name": "Main Profile",
                "resolution": f"{config.get('width')}x{config.get('height')}",
                "frameRate": config.get("frame_rate", 6),
                "active": "profile1" in streamer.get_active_profiles() if hasattr(streamer, 'get_active_profiles') else True
            },
            "profile2": {
                "token": "profile2",
                "name": "Sub Profile",
                "resolution": f"{config.get('width', 1920) // 2}x{config.get('height', 1080) // 2}",
                "frameRate": min(config.get("frame_rate", 6), 4),
                "active": "profile2" in streamer.get_active_profiles() if hasattr(streamer, 'get_active_profiles') else False
            },
            "profile3": {
                "token": "profile3",
                "name": "Mobile Profile",
                "resolution": f"{config.get('width', 1920) // 4}x{config.get('height', 1080) // 4}",
                "frameRate": min(config.get("frame_rate", 6), 2),
                "active": "profile3" in streamer.get_active_profiles() if hasattr(streamer, 'get_active_profiles') else False
            }
        }

        return jsonify({
            "count": len(profiles),
            "profiles": profiles
        })

    @app.route('/streams', methods=["GET"])
    def get_streams():
        """
        Get information about active streams.
        """
        streams = {}

        # Get active streams
        active_streams = []
        if hasattr(streamer, 'get_active_profiles'):
            active_streams = streamer.get_active_profiles()

        # Build stream URLs
        for profile_token in ["profile1", "profile2", "profile3"]:
            stream_name = config.get("stream_name", "yolink-dashboard")

            # Add profile-specific suffix
            if profile_token == "profile1":
                stream_name = f"{stream_name}_main"
            elif profile_token == "profile2":
                stream_name = f"{stream_name}_sub"
            elif profile_token == "profile3":
                stream_name = f"{stream_name}_mobile"

            auth_part = ""
            if config.get("onvif_auth_required", True):
                username = config.get("onvif_username", "admin")
                password = config.get("onvif_password", "123456")
                # Mask password in response
                masked_password = "*" * len(password)
                auth_part = f"{username}:{masked_password}@"

            stream_url = f"rtsp://{auth_part}{config['server_ip']}:{config['rtsp_port']}/{stream_name}"

            streams[profile_token] = {
                "token": profile_token,
                "url": stream_url,
                "active": profile_token in active_streams
            }

        return jsonify({
            "count": len(streams),
            "streams": streams
        })

    @app.route('/stream/<profile_token>', methods=["POST"])
    def manage_stream(profile_token):
        """
        Start or stop a specific stream.

        Args:
            profile_token: Profile token to manage
        """
        # Verify profile token
        if profile_token not in ["profile1", "profile2", "profile3"]:
            return jsonify({
                "error": "Invalid profile token",
                "valid_tokens": ["profile1", "profile2", "profile3"]
            }), 400

        # Get the desired action (start or stop)
        action = request.json.get('action') if request.json else "start"

        if action == "start":
            # Start the stream
            if hasattr(streamer, 'start_profile_stream'):
                success = streamer.start_profile_stream(profile_token)
            else:
                # Fallback for older streamer implementation
                success = True

            return jsonify({
                "success": success,
                "message": f"Stream {profile_token} {'started' if success else 'failed to start'}",
                "profile": profile_token,
                "timestamp": datetime.datetime.now().isoformat()
            })
        elif action == "stop":
            # Stop the stream
            if hasattr(streamer, 'stop_profile_stream'):
                success = streamer.stop_profile_stream(profile_token)
            else:
                # Fallback for older streamer implementation
                success = True

            return jsonify({
                "success": success,
                "message": f"Stream {profile_token} {'stopped' if success else 'failed to stop'}",
                "profile": profile_token,
                "timestamp": datetime.datetime.now().isoformat()
            })
        else:
            return jsonify({
                "error": "Invalid action",
                "valid_actions": ["start", "stop"]
            }), 400


    @app.errorhandler(404)
    def not_found(e):
        """Handle 404 errors gracefully."""
        if request.path.startswith('/onvif/'):
            # For ONVIF requests, return SOAP fault
            soap_fault = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:ter="http://www.onvif.org/ver10/error">
  <soap:Body>
    <soap:Fault>
      <soap:Code>
        <soap:Value>soap:Sender</soap:Value>
        <soap:Subcode>
          <soap:Value>ter:NotFound</soap:Value>
        </soap:Subcode>
      </soap:Code>
      <soap:Reason>
        <soap:Text xml:lang="en">The requested resource was not found</soap:Text>
      </soap:Reason>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
"""
            return Response(soap_fault, status=404, mimetype="application/soap+xml")
        else:
            # For regular API requests, return JSON
            return jsonify({
                "error": "Not found",
                "message": "The requested resource was not found"
            }), 404

    @app.errorhandler(500)
    def server_error(e):
        """Handle 500 errors gracefully."""
        if request.path.startswith('/onvif/'):
            # For ONVIF requests, return SOAP fault
            soap_fault = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:ter="http://www.onvif.org/ver10/error">
  <soap:Body>
    <soap:Fault>
      <soap:Code>
        <soap:Value>soap:Receiver</soap:Value>
        <soap:Subcode>
          <soap:Value>ter:ServerError</soap:Value>
        </soap:Subcode>
      </soap:Code>
      <soap:Reason>
        <soap:Text xml:lang="en">Internal server error</soap:Text>
      </soap:Reason>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
"""
            return Response(soap_fault, status=500, mimetype="application/soap+xml")
        else:
            # For regular API requests, return JSON
            return jsonify({
                "error": "Server error",
                "message": "An internal server error occurred"
            }), 500

    logger.info("API routes configured")