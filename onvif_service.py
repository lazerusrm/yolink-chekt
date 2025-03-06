"""
ONVIF service for device discovery and interaction.
"""
import uuid
import socket
import logging
import threading
from typing import Dict, Any

logger = logging.getLogger(__name__)


class OnvifService(threading.Thread):
    """
    ONVIF service for camera device discovery and interaction.
    Implements WS-Discovery for announcing the RTSP stream as an ONVIF camera.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the ONVIF service.

        Args:
            config: Application configuration
        """
        super().__init__()
        self.config = config
        self.server_ip = config.get("server_ip")
        self.onvif_port = config.get("onvif_port", 80)
        self.rtsp_port = config.get("rtsp_port", 554)
        self.stream_name = config.get("stream_name", "yolink-dashboard")

        # Generate unique device identifiers
        self.device_info = {
            "Manufacturer": "YoLink",
            "Model": "Dashboard-RTSP",
            "FirmwareVersion": "1.0.0",
            "SerialNumber": str(uuid.uuid4()),
            "HardwareId": "YOLINK-DASHBOARD-1"
        }

        # RTSP stream URL
        self.rtsp_url = f"rtsp://{self.server_ip}:{self.rtsp_port}/{self.stream_name}"

        # Thread settings
        self.daemon = True
        self.running = True

    def run(self) -> None:
        """
        Thread main function. Starts WS-Discovery service.
        """
        logger.info(f"Starting ONVIF service on port {self.onvif_port}")
        logger.info(f"ONVIF service initialized: onvif://{self.server_ip}:{self.onvif_port}")

        # Start WS-Discovery service in a separate thread
        discovery_thread = threading.Thread(target=self._ws_discovery, daemon=True)
        discovery_thread.start()

    def _ws_discovery(self) -> None:
        """
        Implement WS-Discovery for ONVIF device announcement.
        """
        # Create UDP socket for WS-Discovery
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("", 3702))  # Standard WS-Discovery port
        except Exception as e:
            logger.error(f"WS-Discovery bind error: {e}")
            return

        # Enable broadcast
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        logger.info("WS-Discovery listening on UDP 3702")

        # Process incoming discovery requests
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)

                # Look for Probe messages
                if b"Probe" in data:
                    logger.debug(f"Received WS-Discovery probe from {addr}")

                    # Send ProbeMatch response
                    response = self._generate_probe_match_response()
                    sock.sendto(response.encode(), addr)
                    logger.debug(f"Sent WS-Discovery response to {addr}")

            except Exception as e:
                if self.running:  # Only log if we're still supposed to be running
                    logger.error(f"WS-Discovery error: {e}")

    def _generate_probe_match_response(self) -> str:
        """
        Generate a WS-Discovery ProbeMatch response.

        Returns:
            str: SOAP XML response
        """
        return f"""
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
    <a:To>s:Sender</a:To>
  </s:Header>
  <s:Body>
    <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <d:ProbeMatch>
        <a:EndpointReference><a:Address>urn:uuid:{self.device_info['SerialNumber']}</a:Address></a:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:Scopes>onvif://www.onvif.org/name/YoLinkDashboard</d:Scopes>
        <d:XAddrs>http://{self.server_ip}:{self.onvif_port}/onvif/device_service</d:XAddrs>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>
"""

    def stop(self) -> None:
        """
        Stop the ONVIF service.
        """
        logger.info("Stopping ONVIF service")
        self.running = False