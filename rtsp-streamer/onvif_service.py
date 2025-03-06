"""
ONVIF service for device discovery and interaction.
Implements WS-Discovery and core ONVIF services with optimized resource usage.
"""
import uuid
import socket
import logging
import threading
import base64
import hashlib
import datetime
import http.server
import socketserver
import xml.etree.ElementTree as ET
import time
import os
from config import MAC_ADDRESS, generate_random_mac
import weakref
import ipaddress
import re
from typing import Dict, Any, Optional, List, Callable
from urllib.parse import urlparse, parse_qs
from functools import lru_cache

logger = logging.getLogger(__name__)

# ONVIF XML namespaces - precomputed for efficiency
NS = {
    'soap': 'http://www.w3.org/2003/05/soap-envelope',
    'wsa': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
    'wsd': 'http://schemas.xmlsoap.org/ws/2005/04/discovery',
    'tds': 'http://www.onvif.org/ver10/device/wsdl',
    'trt': 'http://www.onvif.org/ver10/media/wsdl',
    'tt': 'http://www.onvif.org/ver10/schema',
    'wsnt': 'http://docs.oasis-open.org/wsn/b-2',
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    's': 'http://www.w3.org/2003/05/soap-envelope',  # Sometimes used instead of soap
    'ter': 'http://www.onvif.org/ver10/error'  # Error namespace
}

# Register namespace prefixes for pretty XML output
for prefix, uri in NS.items():
    ET.register_namespace(prefix, uri)

# Security utility functions
@lru_cache(maxsize=128)  # Cache digest computations to save CPU
def generate_nonce() -> str:
    """Generate a random nonce for digest authentication."""
    return base64.b64encode(uuid.uuid4().bytes[:16]).decode('utf-8')


def generate_timestamp() -> str:
    """Generate a timestamp in UTC format for authentication."""
    return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def compute_password_digest(nonce: str, created: str, password: str) -> str:
    """
    Compute the password digest according to WS-Security UsernameToken Profile.

    Args:
        nonce: Base64 encoded nonce
        created: Timestamp string
        password: Clear text password

    Returns:
        Base64 encoded password digest
    """
    nonce_bytes = base64.b64decode(nonce)
    digest_input = nonce_bytes + created.encode('utf-8') + password.encode('utf-8')
    password_digest = base64.b64encode(hashlib.sha1(digest_input).digest()).decode('utf-8')
    return password_digest


# XML helper functions
def parse_xml_safely(xml_string: str) -> Optional[ET.Element]:
    """
    Parse XML with safety measures against common attacks.

    Args:
        xml_string: XML string to parse

    Returns:
        ET.Element: Parsed XML root element or None if parsing failed
    """
    if not xml_string or not isinstance(xml_string, str):
        logger.warning("Invalid input: XML string is empty or not a string")
        return None

    try:
        # Default parser prevents entity expansion since Python 3.7.1
        return ET.fromstring(xml_string)
    except ET.ParseError as e:
        logger.warning(f"XML parse error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error parsing XML: {e}")
        return None


class XMLGenerator:
    """Helper class to generate ONVIF XML responses efficiently."""

    @staticmethod
    def generate_soap_response(action: str, body_content: str, msg_id: Optional[str] = None) -> str:
        """
        Generate a SOAP response with the proper headers.

        Args:
            action: The action URI for the response
            body_content: The XML content for the SOAP body
            msg_id: Optional message ID to include in the response

        Returns:
            str: Complete SOAP envelope XML
        """
        if msg_id is None:
            msg_id = f"urn:uuid:{uuid.uuid4()}"

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:tt="http://www.onvif.org/ver10/schema"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
  <soap:Header>
    <wsa:Action>{action}</wsa:Action>
    <wsa:MessageID>{msg_id}</wsa:MessageID>
    <wsa:RelatesTo>uuid:placeholder</wsa:RelatesTo>
  </soap:Header>
  <soap:Body>
    {body_content}
  </soap:Body>
</soap:Envelope>
"""

    @staticmethod
    def generate_fault_response(reason: str, subcode: Optional[str] = None) -> str:
        """
        Generate a SOAP Fault response with ONVIF-specific error codes.

        Args:
            reason: Fault reason text
            subcode: ONVIF-specific error subcode (e.g. "ter:InvalidArgVal")

        Returns:
            str: SOAP fault XML
        """
        subcode_xml = ""
        if subcode:
            subcode_xml = f"""
        <soap:Subcode>
          <soap:Value>{subcode}</soap:Value>
        </soap:Subcode>"""

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:ter="http://www.onvif.org/ver10/error">
  <soap:Body>
    <soap:Fault>
      <soap:Code>
        <soap:Value>soap:Sender</soap:Value>{subcode_xml}
      </soap:Code>
      <soap:Reason>
        <soap:Text xml:lang="en">{reason}</soap:Text>
      </soap:Reason>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
"""


class ProfileInfo:
    """
    Holds information about an ONVIF media profile with thread-safe access.
    """
    def __init__(self, token: str, name: str, width: int, height: int, fps: int,
                 encoding: str = "H264", sensors_per_page: int = 20):
        self.token = token
        self.name = name
        self.width = width
        self.height = height
        self.fps = fps
        self.encoding = encoding
        self.sensors_per_page = sensors_per_page
        self.active = False
        self.lock = threading.RLock()

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary."""
        with self.lock:
            return {
                'token': self.token,
                'name': self.name,
                'resolution': {
                    'width': self.width,
                    'height': self.height
                },
                'fps': self.fps,
                'encoding': self.encoding,
                'sensors_per_page': self.sensors_per_page,
                'active': self.active
            }

    def update(self, **kwargs) -> None:
        """Update profile attributes."""
        with self.lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)

    def activate(self) -> None:
        """Mark profile as active."""
        with self.lock:
            self.active = True

    def deactivate(self) -> None:
        """Mark profile as inactive."""
        with self.lock:
            self.active = False


class OnvifRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP request handler for ONVIF SOAP services.
    Optimized for resource usage and response time.
    """
    server_version = "ONVIF/1.0"
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, service=None, **kwargs):
        self.service = service
        super().__init__(*args, **kwargs)

    def do_POST(self):
        """Handle ONVIF SOAP POST requests."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "Missing request body")
                return

            if content_length > 1024 * 1024:  # 1MB limit
                self.send_error(413, "Request body too large")
                return

            soap_request = self.rfile.read(content_length).decode('utf-8')

            if not soap_request.strip().startswith('<'):
                self.send_error(400, "Invalid request format")
                return

            if not self._check_authentication(soap_request):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="ONVIF"')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Authentication required")
                return

            service_path = self.path.lower()
            response = ""

            if '/onvif/device_service' in service_path:
                response = self.service.handle_device_service(soap_request)
            elif '/onvif/media_service' in service_path:
                response = self.service.handle_media_service(soap_request)
            else:
                self.send_error(404, "Service not found")
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/soap+xml; charset=utf-8')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))

        except Exception as e:
            logger.error(f"Request processing error: {e}")
            self.send_error(500, "Internal server error")

    def _check_authentication(self, soap_request: str) -> bool:
        """
        Enhanced authentication handler with detailed logging.

        Args:
            soap_request: The SOAP request XML

        Returns:
            bool: True if authentication is valid or not required
        """
        # For initial testing, accept all auth to verify other ONVIF methods
        # Change STRICT_AUTH to True when ready to enforce proper auth
        STRICT_AUTH = False

        # Log current settings for diagnostics
        logger.info(f"ONVIF Auth Settings - Required: {self.service.authentication_required}, "
                    f"Username: {self.service.username}, Password: {'*' * (len(self.service.password) - 2)}**")

        # Skip authentication if not required
        if not self.service.authentication_required:
            logger.info("Authentication not required, accepting request")
            return True

        # CHECK 1: Basic Authentication
        auth_header = self.headers.get('Authorization')
        if auth_header:
            logger.info(f"Found Authorization header: {auth_header[:10]}...")

            if auth_header.startswith('Basic '):
                try:
                    auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    username, password = auth_decoded.split(':', 1)
                    logger.info(f"Basic auth attempt with username: {username}")

                    # The critical comparison
                    if username == self.service.username and password == self.service.password:
                        logger.info("Basic auth successful!")
                        return True
                    else:
                        # Log the exact strings for debugging (careful with real passwords)
                        logger.warning(
                            f"Basic auth failed: Expected '{self.service.username}'/'{self.service.password}' "
                            f"but got '{username}'/'{password}'")
                except Exception as e:
                    logger.warning(f"Error parsing Basic auth: {e}")

        # CHECK 2: Try to extract directly from SOAP body as a fallback
        try:
            if "<Username>" in soap_request and "<Password>" in soap_request:
                username_start = soap_request.find("<Username>") + len("<Username>")
                username_end = soap_request.find("</Username>", username_start)
                password_start = soap_request.find("<Password>") + len("<Password>")
                password_end = soap_request.find("</Password>", password_start)

                if username_end > username_start and password_end > password_start:
                    soap_username = soap_request[username_start:username_end]
                    soap_password = soap_request[password_start:password_end]

                    logger.info(f"Found credentials in SOAP: username='{soap_username}'")

                    if soap_username == self.service.username and soap_password == self.service.password:
                        logger.info("SOAP body credentials match!")
                        return True
                    else:
                        logger.warning(f"SOAP credentials mismatch: Got username='{soap_username}'")
        except Exception as e:
            logger.warning(f"Error extracting credentials from SOAP: {e}")

        # CHECK 3: Last resort for debugging - always accept if strict auth is off
        if not STRICT_AUTH:
            logger.warning("⚠️ Authentication bypassed for testing! ⚠️")
            return True

        # Authentication failed
        logger.warning("❌ Authentication failed - all methods tried")
        return False

    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"{self.address_string()} - {format % args}")


class OnvifHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server for ONVIF services."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, service):
        self.service = service
        self.active_connections = set()
        self.connection_lock = threading.Lock()
        super().__init__(server_address, self.handler_class)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        with self.connection_lock:
            self.active_connections.add(request)

        try:
            self.RequestHandlerClass(request, client_address, self, service=self.service)
        finally:
            with self.connection_lock:
                if request in self.active_connections:
                    self.active_connections.remove(request)

    def handler_class(self, *args, **kwargs):
        return OnvifRequestHandler(*args, **kwargs)

    def shutdown_request(self, request):
        """Called to shutdown and close an individual request."""
        with self.connection_lock:
            if request in self.active_connections:
                self.active_connections.remove(request)
        super().shutdown_request(request)

    def close_all_connections(self):
        """Close all active connections."""
        with self.connection_lock:
            for conn in list(self.active_connections):
                try:
                    conn.close()
                except Exception:
                    pass
            self.active_connections.clear()

    def server_bind(self):
        """Bind the server and set socket options for better stability."""
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Set a longer timeout for better stability
        self.socket.settimeout(60)  # 60 seconds timeout
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()


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
        super().__init__(daemon=True)
        self.config = config

        self.server_ip = config.get("server_ip", "0.0.0.0")
        self.announce_ip = config.get("announce_ip", self.server_ip)
        self.onvif_port = int(config.get("onvif_port", 80))
        self.rtsp_port = int(config.get("rtsp_port", 554))
        self.stream_name = config.get("stream_name", "yolink-dashboard")

        self.authentication_required = config.get("onvif_auth_required", True)
        self.username = config.get("onvif_username", "admin")
        self.password = config.get("onvif_password", "123456")

        self.device_uuid = str(uuid.uuid4())
        self.mac_address = os.getenv("MAC_ADDRESS")
        if not self.mac_address:
            self.mac_address = generate_random_mac()
        self.device_info = {
            "Manufacturer": config.get("manufacturer", "Industrial Camera Systems"),
            "Model": config.get("model", "Dashboard-RTSP"),
            "FirmwareVersion": config.get("firmware_version", "1.0.1"),
            "SerialNumber": self.device_uuid,
            "HardwareId": config.get("hardware_id", "YLK-Dashboard")
        }

        self.device_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/device_service"
        self.media_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/media_service"
        self.events_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/events_service"

        self.http_server = None
        self.discovery_socket = None
        self.discovery_thread = None
        self.last_announce_time = 0
        self.announce_interval = 300

        self.profiles_lock = threading.RLock()
        self.media_profiles = []
        self.media_profiles.append(
            ProfileInfo(
                token="profile1",
                name="Dashboard Main Stream",
                width=config.get("width", 1920),
                height=config.get("height", 1080),
                fps=config.get("frame_rate", 6),
                sensors_per_page=config.get("sensors_per_page", 20)
            )
        )
        self.media_profiles.append(
            ProfileInfo(
                token="profile2",
                name="Dashboard Low Stream",
                width=config.get("low_res_width", config.get("width", 1920) // 2),
                height=config.get("low_res_height", config.get("height", 1080) // 2),
                fps=config.get("low_res_fps", min(config.get("frame_rate", 6), 4)),
                sensors_per_page=config.get("low_res_sensors_per_page", 6)
            )
        )
        self.media_profiles.append(
            ProfileInfo(
                token="profile3",
                name="Dashboard Mobile Stream",
                width=config.get("mobile_width", config.get("width", 1920) // 4),
                height=config.get("mobile_height", config.get("height", 1080) // 4),
                fps=config.get("mobile_fps", 2),
                sensors_per_page=config.get("mobile_sensors_per_page", 4)
            )
        )

        self.profile_callbacks = {}
        self.running = True
        self.lock = threading.RLock()

    def register_profile_callback(self, callback: Callable[[str], bool]) -> None:
        """
        Register a callback to be called when a profile is requested.

        Args:
            callback: Function to call with profile token when a profile is requested
        """
        with self.profiles_lock:
            self.profile_callbacks["default"] = callback
            logger.info("Profile callback registered")

    def register_profile_specific_callback(self, profile_token: str, callback: Callable[[str], bool]) -> None:
        """
        Register a callback for a specific profile.

        Args:
            profile_token: Token of the profile to register for
            callback: Function to call when this profile is requested
        """
        with self.profiles_lock:
            self.profile_callbacks[profile_token] = callback
            logger.info(f"Profile-specific callback registered for {profile_token}")

    def run(self) -> None:
        """Thread main function. Starts WS-Discovery service and HTTP services."""
        logger.info(f"Starting ONVIF service on port {self.onvif_port}")
        logger.info(f"ONVIF device service: {self.device_service_url}")

        try:
            self._start_http_server()
            self._start_discovery_thread()
            while self.running:
                time.sleep(1)
        except Exception as e:
            logger.error(f"Error in ONVIF service: {e}")
        finally:
            self._cleanup()

    def _start_http_server(self) -> None:
        """Start the HTTP server for ONVIF services."""
        try:
            self.http_server = OnvifHTTPServer((self.server_ip, self.onvif_port), self)
            http_thread = threading.Thread(
                target=self.http_server.serve_forever,
                daemon=True,
                name="onvif-http"
            )
            http_thread.start()
            logger.info(f"ONVIF HTTP server running on port {self.onvif_port}")
        except Exception as e:
            logger.error(f"Failed to start ONVIF HTTP server: {e}")
            raise

    def _start_discovery_thread(self) -> None:
        """Start the WS-Discovery service in a separate thread."""
        self.discovery_thread = threading.Thread(
            target=self._ws_discovery,
            daemon=True,
            name="ws-discovery"
        )
        self.discovery_thread.start()
        logger.info("WS-Discovery service started")

    def _ws_discovery(self) -> None:
        """Implement WS-Discovery for ONVIF device announcement with improved reliability."""
        try:
            # Create socket with broadcast capability
            self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcasting

            # Set a larger buffer size to handle more incoming requests
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)

            # Bind to all interfaces on the ONVIF discovery port
            self.discovery_socket.bind(('0.0.0.0', 3702))

            # Join the ONVIF multicast group
            mreq = socket.inet_aton('239.255.255.250') + socket.inet_aton('0.0.0.0')
            self.discovery_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            # Set a reasonable timeout to allow for loop responsiveness
            self.discovery_socket.settimeout(0.5)

            logger.info(f"WS-Discovery listening on UDP 3702, advertising services at {self.server_ip}")
            logger.info(f"Device service URL: {self.device_service_url}")
            logger.info(f"Media service URL: {self.media_service_url}")

            # Send initial announcement immediately
            self._send_hello_announcement()

            # Discovery loop
            while self.running:
                try:
                    # Send periodic announcements
                    current_time = time.time()
                    if current_time - self.last_announce_time > self.announce_interval:
                        self._send_hello_announcement()

                    # Listen for incoming discovery messages
                    data, addr = self.discovery_socket.recvfrom(8192)  # Larger buffer for incoming messages

                    # Debug the raw message if needed
                    if os.environ.get('DEBUG_DISCOVERY') == 'true':
                        logger.debug(f"Received WS-Discovery message from {addr}: {data[:200]}...")

                    # Handle ONVIF ProbeMatches
                    if b"Probe" in data:
                        logger.info(f"Received WS-Discovery probe from {addr}")
                        response = self._generate_probe_match_response()
                        self.discovery_socket.sendto(response.encode('utf-8'), addr)
                        logger.info(f"Sent WS-Discovery ProbeMatch response to {addr}")

                    # Handle direct messages
                    elif b"GetSystemDateAndTime" in data or b"GetCapabilities" in data:
                        logger.info(f"Received direct ONVIF message from {addr}, redirecting to API")
                        # Could add code here to handle direct SOAP requests if needed

                except socket.timeout:
                    # Normal timeout, just continue the loop
                    pass
                except Exception as e:
                    if self.running:
                        logger.error(f"WS-Discovery error: {e}")
                        if os.environ.get('DEBUG_DISCOVERY') == 'true':
                            logger.error(f"Exception details: {traceback.format_exc()}")
                        # Short sleep to prevent tight loop in case of persistent errors
                        time.sleep(1)

                        # Brief sleep to prevent CPU hogging while still being responsive
                time.sleep(0.05)

        except Exception as e:
            logger.error(f"Error initializing WS-Discovery service: {e}")
            logger.error(f"Exception details: {traceback.format_exc()}")
        finally:
            # Clean up the socket on exit
            if self.discovery_socket:
                try:
                    self.discovery_socket.close()
                    logger.info("WS-Discovery socket closed")
                except Exception as close_error:
                    logger.error(f"Error closing discovery socket: {close_error}")
                self.discovery_socket = None

    def _send_hello_announcement(self) -> None:
        """
        Send a WS-Discovery Hello announcement to advertise the device.
        Uses both multicast and broadcast for better discovery in complex networks.
        """
        if not self.discovery_socket:
            logger.warning("Cannot send Hello announcement: discovery socket not initialized")
            return

        try:
            # Generate the Hello message using the existing method
            hello_msg = self._generate_hello_message()
            encoded_msg = hello_msg.encode('utf-8')

            # Send to standard ONVIF multicast address
            self.discovery_socket.sendto(encoded_msg, ('239.255.255.250', 3702))

            # Also send as broadcast for networks that might block multicast
            try:
                self.discovery_socket.sendto(encoded_msg, ('255.255.255.255', 3702))
            except Exception as broadcast_error:
                logger.warning(f"Broadcast send failed, falling back to multicast only: {broadcast_error}")

            # Update the timestamp for when we last sent an announcement
            self.last_announce_time = time.time()

            # Log detailed announcement information in debug mode
            if os.environ.get('DEBUG_DISCOVERY') == 'true':
                logger.info(f"Hello announcement sent with details:")
                logger.info(f"  - Device UUID: {self.device_uuid}")
                logger.info(f"  - Server IP: {self.server_ip}")
                logger.info(f"  - Device Service URL: {self.device_service_url}")
                logger.info(f"  - Media Service URL: {self.media_service_url}")
            else:
                logger.info("Sent WS-Discovery Hello announcement via multicast and broadcast")

        except Exception as e:
            logger.error(f"Failed to send Hello announcement: {e}")
            if os.environ.get('DEBUG_DISCOVERY') == 'true':
                logger.error(f"Exception details: {traceback.format_exc()}")

    def _generate_hello_message(self) -> str:
        """
        Generate a WS-Discovery Hello message.

        Returns:
            str: SOAP XML Hello message
        """
        return f"""
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</a:Action>
    <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body>
    <d:Hello>
      <a:EndpointReference><a:Address>urn:uuid:{self.device_uuid}</a:Address></a:EndpointReference>
      <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
      <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/YoLinkDashboard onvif://www.onvif.org/location/Dashboard onvif://www.onvif.org/hardware/{self.device_uuid}</d:Scopes>
      <d:XAddrs>{self.device_service_url} {self.media_service_url}</d:XAddrs>
      <d:MetadataVersion>1</d:MetadataVersion>
    </d:Hello>
  </s:Body>
</s:Envelope>
"""

    def handle_device_service(self, soap_request: str) -> str:
        """
        Handle ONVIF Device service requests.
        Now also handles media requests for better compatibility with some clients.

        Args:
            soap_request: SOAP request XML

        Returns:
            str: SOAP response XML
        """
        try:
            root = parse_xml_safely(soap_request)
            if root is None:
                return XMLGenerator.generate_fault_response("Invalid SOAP request")

            body = root.find('.//soap:Body', NS)
            if body is None:
                return XMLGenerator.generate_fault_response("Invalid SOAP request")

            action_element = None
            for child in body:
                if child.tag.startswith("{"):
                    action_element = child
                    break

            if action_element is None:
                return XMLGenerator.generate_fault_response("No action element found")

            local_name = action_element.tag.split('}')[-1]

            # Define media service actions that might be sent to device endpoint
            media_actions = {
                'GetProfiles', 'GetProfile', 'GetStreamUri', 'GetSnapshotUri',
                'GetVideoEncoderConfigurations', 'GetVideoSources', 'GetVideoSourceConfigurations',
                'GetVideoSourceConfigurationOptions', 'GetAudioSourceConfigurations',
                'GetCompatibleVideoEncoderConfigurations', 'GetVideoEncoderConfigurationOptions'
            }

            # If this is a media action, redirect to the media service handler
            if local_name in media_actions:
                logger.info(f"Redirecting media action '{local_name}' from device service to media service")
                return self.handle_media_service(soap_request)

            # Regular device service actions
            handler_map = {
                'GetDeviceInformation': self._handle_get_device_information,
                'GetServices': self._handle_get_services,
                'GetCapabilities': self._handle_get_capabilities,
                'GetServiceCapabilities': lambda r: self._handle_get_service_capabilities(r, 'device'),
                'GetScopes': self._handle_get_scopes,
                'GetSystemDateAndTime': self._handle_get_system_date_and_time,
                'GetHostname': self._handle_get_hostname,
                'GetNetworkInterfaces': self._handle_get_network_interfaces,
                'GetNetworkProtocols': self._handle_get_network_protocols,  # <- Missing comma was here
                'GetVideoSourceConfigurationOptions': self._handle_get_video_source_configuration_options,
                'GetAudioSourceConfigurations': self._handle_get_audio_source_configurations,
                'GetCompatibleVideoEncoderConfigurations': self._handle_get_compatible_video_encoder_configurations,
                'GetVideoEncoderConfigurationOptions': self._handle_get_video_encoder_configuration_options
            }

            handler = handler_map.get(local_name)
            if handler:
                return handler(root)
            else:
                logger.warning(f"Unsupported device service action: {local_name}")
                return XMLGenerator.generate_fault_response(
                    f"Unsupported action: {local_name}",
                    "ter:ActionNotSupported"
                )
        except Exception as e:
            logger.error(f"Error handling device service request: {e}")
            return XMLGenerator.generate_fault_response(f"Internal error: {str(e)}")

    def handle_media_service(self, soap_request: str) -> str:
        """
        Handle ONVIF Media service requests with enhanced protocol support.

        Args:
            soap_request: SOAP request XML

        Returns:
            str: SOAP response XML
        """
        try:
            # Debug incoming GetStreamUri requests
            if "GetStreamUri" in soap_request:
                logger.info(f"GetStreamUri request received: {soap_request[:500]}...")

            root = parse_xml_safely(soap_request)
            if root is None:
                return XMLGenerator.generate_fault_response("Invalid SOAP request")

            body = root.find('.//soap:Body', NS)
            if body is None:
                return XMLGenerator.generate_fault_response("Invalid SOAP request")

            action_element = None
            for child in body:
                if child.tag.startswith("{"):
                    action_element = child
                    break

            if action_element is None:
                return XMLGenerator.generate_fault_response("No action element found")

            local_name = action_element.tag.split('}')[-1]

            # Log media service actions for debugging
            logger.info(f"Media service action requested: {local_name}")

            # Add the new handlers for previously unsupported methods
            handler_map = {
                'GetProfiles': self._handle_get_profiles,
                'GetProfile': self._handle_get_profile,
                'GetStreamUri': self._handle_get_stream_uri,
                'GetSnapshotUri': self._handle_get_snapshot_uri,
                'GetVideoEncoderConfigurations': self._handle_get_video_encoder_configurations,
                'GetVideoSourceConfigurations': self._handle_get_video_source_configurations,
                'GetVideoSources': self._handle_get_video_sources,
                'GetServiceCapabilities': lambda r: self._handle_get_service_capabilities(r, 'media'),
                # New handlers for missing methods
                'GetVideoSourceConfigurationOptions': self._handle_get_video_source_configuration_options,
                'GetAudioSourceConfigurations': self._handle_get_audio_source_configurations,
                'GetCompatibleVideoEncoderConfigurations': self._handle_get_compatible_video_encoder_configurations,
                'GetVideoEncoderConfigurationOptions': self._handle_get_video_encoder_configuration_options
            }

            handler = handler_map.get(local_name)
            if handler:
                response = handler(root)

                # Debug response for GetStreamUri
                if local_name == "GetStreamUri":
                    logger.info(f"GetStreamUri response: {response[:500]}...")

                return response
            else:
                logger.warning(f"Unsupported media service action: {local_name}")
                return XMLGenerator.generate_fault_response(
                    f"Unsupported action: {local_name}",
                    "ter:ActionNotSupported"
                )
        except Exception as e:
            logger.error(f"Error handling media service request: {e}")
            return XMLGenerator.generate_fault_response(f"Internal error: {str(e)}")


    def _handle_get_stream_uri(self, request: ET.Element) -> str:
        """
        Handler for GetStreamUri requests with enhanced logging and RTSP URL construction.
        If authentication is required, credentials are included in the URL.
        This version also ensures that the proper stream name is used based on the profile token.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML containing the RTSP stream URI.
        """
        try:
            logger.info("Processing GetStreamUri request")
            body = request.find('.//soap:Body', NS)
            if body is None:
                return XMLGenerator.generate_fault_response("Invalid SOAP request: missing Body")

            get_stream_uri = body.find('.//trt:GetStreamUri', NS)
            if get_stream_uri is None:
                return XMLGenerator.generate_fault_response("Missing GetStreamUri element")

            profile_token_elem = get_stream_uri.find('.//trt:ProfileToken', NS)
            if profile_token_elem is None or not profile_token_elem.text:
                return XMLGenerator.generate_fault_response("Missing ProfileToken")

            token = profile_token_elem.text.strip()
            logger.info(f"GetStreamUri requested for profile token: {token}")

            # Activate the corresponding profile
            with self.profiles_lock:
                for profile_info in self.media_profiles:
                    if profile_info.token == token:
                        profile_info.activate()
                        break

            # Invoke callbacks if registered
            if token in self.profile_callbacks:
                self.profile_callbacks[token](token)
            elif "default" in self.profile_callbacks:
                self.profile_callbacks["default"](token)

            # Determine stream name based on the profile token.
            stream_name = self.stream_name  # default base name
            if token == "profile1":
                stream_name = f"{self.stream_name}_main"
            elif token == "profile2":
                stream_name = f"{self.stream_name}_sub"
            elif token == "profile3":
                stream_name = f"{self.stream_name}_mobile"

            # If authentication is enabled, include credentials in the RTSP URL.
            auth_part = f"{self.username}:{self.password}@" if self.authentication_required else ""

            # Construct the full RTSP URL.
            stream_url = f"rtsp://{auth_part}{self.server_ip}:{self.rtsp_port}/{stream_name}"
            logger.info(f"Providing stream URL: {stream_url}")

            # Extract the message ID if present for response correlation.
            message_id = None
            header = request.find('.//soap:Header', NS)
            if header is not None:
                message_id_elem = header.find('.//wsa:MessageID', NS)
                if message_id_elem is not None and message_id_elem.text:
                    message_id = message_id_elem.text

            response = f"""
        <trt:GetStreamUriResponse>
          <trt:MediaUri>
            <tt:Uri>{stream_url}</tt:Uri>
            <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
            <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
            <tt:Timeout>PT60S</tt:Timeout>
          </trt:MediaUri>
        </trt:GetStreamUriResponse>
        """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
                response,
                message_id
            )
        except Exception as e:
            logger.error(f"Error in GetStreamUri handler: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Internal error: {str(e)}")

    def _handle_get_audio_source_configurations(self, request: ET.Element) -> str:
        """
        Handle GetAudioSourceConfigurations request with an empty response since audio is not supported.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        # Simply return an empty list since we don't support audio yet
        response = """
<trt:GetAudioSourceConfigurationsResponse>
</trt:GetAudioSourceConfigurationsResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetAudioSourceConfigurationsResponse",
            response
        )

    def _handle_get_compatible_video_encoder_configurations(self, request: ET.Element) -> str:
        """
        Handle GetCompatibleVideoEncoderConfigurations request.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        # Get profile token
        profile_token = None
        try:
            profile_token_elem = request.find('.//trt:ProfileToken', NS)
            if profile_token_elem is not None:
                profile_token = profile_token_elem.text
        except Exception as e:
            logger.debug(f"Error getting profile token: {e}")

        # Return the same information as GetVideoEncoderConfigurations
        # but filtered to only include configurations compatible with this profile
        with self.profiles_lock:
            video_encoders = ""
            for profile_info in self.media_profiles:
                # If profile token is specified, only include configurations for that profile
                if profile_token and profile_info.token != profile_token:
                    continue

                profile = profile_info.to_dict()
                video_encoders += f"""
<trt:Configurations token="VideoEncoder_{profile['token']}">
  <tt:Name>VideoEncoder_{profile['token']}</tt:Name>
  <tt:UseCount>1</tt:UseCount>
  <tt:Encoding>{profile['encoding']}</tt:Encoding>
  <tt:Resolution>
    <tt:Width>{profile['resolution']['width']}</tt:Width>
    <tt:Height>{profile['resolution']['height']}</tt:Height>
  </tt:Resolution>
  <tt:Quality>5</tt:Quality>
  <tt:RateControl>
    <tt:FrameRateLimit>{profile['fps']}</tt:FrameRateLimit>
    <tt:EncodingInterval>1</tt:EncodingInterval>
    <tt:BitrateLimit>4096</tt:BitrateLimit>
  </tt:RateControl>
  <tt:H264>
    <tt:GovLength>30</tt:GovLength>
    <tt:H264Profile>High</tt:H264Profile>
  </tt:H264>
  <tt:Multicast>
    <tt:Address>
      <tt:Type>IPv4</tt:Type>
      <tt:IPv4Address>0.0.0.0</tt:IPv4Address>
    </tt:Address>
    <tt:Port>0</tt:Port>
    <tt:TTL>1</tt:TTL>
    <tt:AutoStart>false</tt:AutoStart>
  </tt:Multicast>
  <tt:SessionTimeout>PT60S</tt:SessionTimeout>
</trt:Configurations>
"""

        response = f"""
<trt:GetCompatibleVideoEncoderConfigurationsResponse>
{video_encoders}
</trt:GetCompatibleVideoEncoderConfigurationsResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetCompatibleVideoEncoderConfigurationsResponse",
            response
        )

    def _handle_get_device_information(self, request: ET.Element) -> str:
        """
        Handle GetDeviceInformation request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        response = f"""
<tds:GetDeviceInformationResponse>
  <tds:Manufacturer>{self.device_info['Manufacturer']}</tds:Manufacturer>
  <tds:Model>{self.device_info['Model']}</tds:Model>
  <tds:FirmwareVersion>{self.device_info['FirmwareVersion']}</tds:FirmwareVersion>
  <tds:SerialNumber>{self.device_info['SerialNumber']}</tds:SerialNumber>
  <tds:HardwareId>{self.device_info['HardwareId']}</tds:HardwareId>
</tds:GetDeviceInformationResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse",
            response
        )

    def _handle_get_services(self, request: ET.Element) -> str:
        """
        Handle GetServices request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        include_capability = True
        body = request.find('.//soap:Body', NS)
        if body is not None:
            get_services = body.find('.//tds:GetServices', NS)
            if get_services is not None:
                include_capability_elem = get_services.find('.//tds:IncludeCapability', NS)
                if include_capability_elem is not None:
                    include_capability = include_capability_elem.text.lower() == 'true'

        capability_device = ""
        capability_media = ""
        if include_capability:
            capability_device = """
<tds:Capabilities>
  <tt:Device>
    <tt:XAddr>http://www.onvif.org/ver10/device/wsdl</tt:XAddr>
    <tt:Network>
      <tt:IPFilter>false</tt:IPFilter>
      <tt:ZeroConfiguration>false</tt:ZeroConfiguration>
      <tt:IPVersion6>false</tt:IPVersion6>
      <tt:DynDNS>false</tt:DynDNS>
    </tt:Network>
    <tt:System>
      <tt:DiscoveryResolve>true</tt:DiscoveryResolve>
      <tt:DiscoveryBye>true</tt:DiscoveryBye>
      <tt:RemoteDiscovery>true</tt:RemoteDiscovery>
      <tt:SystemBackup>false</tt:SystemBackup>
      <tt:SystemLogging>false</tt:SystemLogging>
      <tt:FirmwareUpgrade>false</tt:FirmwareUpgrade>
      <tt:SupportedVersions>
        <tt:Major>1</tt:Major>
        <tt:Minor>0</tt:Minor>
      </tt:SupportedVersions>
    </tt:System>
    <tt:Security>
      <tt:TLS1.1>false</tt:TLS1.1>
      <tt:TLS1.2>false</tt:TLS1.2>
      <tt:OnboardKeyGeneration>false</tt:OnboardKeyGeneration>
      <tt:AccessPolicyConfig>false</tt:AccessPolicyConfig>
      <tt:DefaultAccessPolicy>false</tt:DefaultAccessPolicy>
      <tt:Dot1X>false</tt:Dot1X>
      <tt:RemoteUserHandling>false</tt:RemoteUserHandling>
      <tt:X.509Token>false</tt:X.509Token>
      <tt:SAMLToken>false</tt:SAMLToken>
      <tt:KerberosToken>false</tt:KerberosToken>
      <tt:UsernameToken>true</tt:UsernameToken>
      <tt:HttpDigest>false</tt:HttpDigest>
      <tt:RELToken>false</tt:RELToken>
    </tt:Security>
  </tt:Device>
</tds:Capabilities>
"""
            capability_media = """
<tds:Capabilities>
  <tt:Media>
    <tt:XAddr>http://www.onvif.org/ver10/media/wsdl</tt:XAddr>
    <tt:StreamingCapabilities>
      <tt:RTPMulticast>false</tt:RTPMulticast>
      <tt:RTP_TCP>true</tt:RTP_TCP>
      <tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
    </tt:StreamingCapabilities>
  </tt:Media>
</tds:Capabilities>
"""

        response = f"""
<tds:GetServicesResponse>
  <tds:Service>
    <tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>
    <tds:XAddr>{self.device_service_url}</tds:XAddr>
    <tds:Version>
      <tt:Major>1</tt:Major>
      <tt:Minor>0</tt:Minor>
    </tds:Version>
    {capability_device}
  </tds:Service>
  <tds:Service>
    <tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>
    <tds:XAddr>{self.media_service_url}</tds:XAddr>
    <tds:Version>
      <tt:Major>1</tt:Major>
      <tt:Minor>0</tt:Minor>
    </tds:Version>
    {capability_media}
  </tds:Service>
</tds:GetServicesResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetServicesResponse",
            response
        )

    def _handle_get_profiles(self, request: ET.Element) -> str:
        """
        Simplified handler for GetProfiles request.
        Provides a minimal, standard-compliant response.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        logger.info("Processing GetProfiles request with simplified response")

        try:
            with self.profiles_lock:
                profiles_xml = ""
                for profile_info in self.media_profiles:
                    profile = profile_info.to_dict()
                    profiles_xml += f"""
    <trt:Profiles fixed="true" token="{profile['token']}">
      <tt:Name>{profile['name']}</tt:Name>
      <tt:VideoSourceConfiguration token="VideoSourceConfig_{profile['token']}">
        <tt:Name>VideoSourceConfig</tt:Name>
        <tt:UseCount>1</tt:UseCount>
        <tt:SourceToken>VideoSource</tt:SourceToken>
        <tt:Bounds height="{profile['resolution']['height']}" width="{profile['resolution']['width']}" y="0" x="0"/>
      </tt:VideoSourceConfiguration>
      <tt:VideoEncoderConfiguration token="VideoEncoder_{profile['token']}">
        <tt:Name>VideoEncoder_{profile['token']}</tt:Name>
        <tt:UseCount>1</tt:UseCount>
        <tt:Encoding>{profile['encoding']}</tt:Encoding>
        <tt:Resolution>
          <tt:Width>{profile['resolution']['width']}</tt:Width>
          <tt:Height>{profile['resolution']['height']}</tt:Height>
        </tt:Resolution>
        <tt:Quality>5</tt:Quality>
        <tt:RateControl>
          <tt:FrameRateLimit>{profile['fps']}</tt:FrameRateLimit>
          <tt:EncodingInterval>1</tt:EncodingInterval>
          <tt:BitrateLimit>4096</tt:BitrateLimit>
        </tt:RateControl>
        <tt:H264>
          <tt:GovLength>30</tt:GovLength>
          <tt:H264Profile>High</tt:H264Profile>
        </tt:H264>
        <tt:Multicast>
          <tt:Address>
            <tt:Type>IPv4</tt:Type>
            <tt:IPv4Address>0.0.0.0</tt:IPv4Address>
          </tt:Address>
          <tt:Port>0</tt:Port>
          <tt:TTL>1</tt:TTL>
          <tt:AutoStart>false</tt:AutoStart>
        </tt:Multicast>
        <tt:SessionTimeout>PT60S</tt:SessionTimeout>
      </tt:VideoEncoderConfiguration>
    </trt:Profiles>
    """

                response = f"""
    <trt:GetProfilesResponse>
    {profiles_xml}
    </trt:GetProfilesResponse>
    """

            logger.info(f"Sending GetProfiles response with {len(self.media_profiles)} profiles")
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error in GetProfiles handler: {e}", exc_info=True)
            # Provide a minimal fallback response
            fallback_response = """
    <trt:GetProfilesResponse>
      <trt:Profiles fixed="true" token="profile1">
        <tt:Name>Main Stream</tt:Name>
        <tt:VideoSourceConfiguration token="VideoSourceConfig_1">
          <tt:Name>VideoSourceConfig</tt:Name>
          <tt:UseCount>1</tt:UseCount>
          <tt:SourceToken>VideoSource</tt:SourceToken>
          <tt:Bounds height="1080" width="1920" y="0" x="0"/>
        </tt:VideoSourceConfiguration>
        <tt:VideoEncoderConfiguration token="VideoEncoder_1">
          <tt:Name>VideoEncoder_1</tt:Name>
          <tt:UseCount>1</tt:UseCount>
          <tt:Encoding>H264</tt:Encoding>
          <tt:Resolution>
            <tt:Width>1920</tt:Width>
            <tt:Height>1080</tt:Height>
          </tt:Resolution>
          <tt:Quality>5</tt:Quality>
          <tt:RateControl>
            <tt:FrameRateLimit>6</tt:FrameRateLimit>
            <tt:EncodingInterval>1</tt:EncodingInterval>
            <tt:BitrateLimit>4096</tt:BitrateLimit>
          </tt:RateControl>
          <tt:H264>
            <tt:GovLength>30</tt:GovLength>
            <tt:H264Profile>High</tt:H264Profile>
          </tt:H264>
          <tt:Multicast>
            <tt:Address>
              <tt:Type>IPv4</tt:Type>
              <tt:IPv4Address>0.0.0.0</tt:IPv4Address>
            </tt:Address>
            <tt:Port>0</tt:Port>
            <tt:TTL>1</tt:TTL>
            <tt:AutoStart>false</tt:AutoStart>
          </tt:Multicast>
          <tt:SessionTimeout>PT60S</tt:SessionTimeout>
        </tt:VideoEncoderConfiguration>
      </trt:Profiles>
    </trt:GetProfilesResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse",
                fallback_response
            )

    def _handle_get_profile(self, request: ET.Element) -> str:
        """
        Handle GetProfile request.
        Since all profiles are always created, no fallback fault is returned if a profile isn't found.
        """
        body = request.find('.//soap:Body', NS)
        if body is None:
            return XMLGenerator.generate_fault_response("Invalid SOAP request")

        get_profile = body.find('.//trt:GetProfile', NS)
        if get_profile is None:
            return XMLGenerator.generate_fault_response("Missing GetProfile element")

        profile_token_elem = get_profile.find('.//trt:ProfileToken', NS)
        if profile_token_elem is None:
            return XMLGenerator.generate_fault_response("Missing ProfileToken")

        token = profile_token_elem.text
        with self.profiles_lock:
            # Unconditionally assume the profile exists as all profiles are always added
            for profile_info in self.media_profiles:
                if profile_info.token == token:
                    profile = profile_info.to_dict()
                    break

        if token in self.profile_callbacks:
            self.profile_callbacks[token](token)
        elif "default" in self.profile_callbacks:
            self.profile_callbacks["default"](token)

        response = f"""
    <trt:GetProfileResponse>
      <trt:Profile fixed="true" token="{profile['token']}">
        <tt:Name>{profile['name']}</tt:Name>
        <tt:VideoSourceConfiguration token="VideoSourceConfig">
          <tt:Name>VideoSourceConfig</tt:Name>
          <tt:UseCount>1</tt:UseCount>
          <tt:SourceToken>VideoSource</tt:SourceToken>
          <tt:Bounds height="{profile['resolution']['height']}" width="{profile['resolution']['width']}" y="0" x="0"/>
        </tt:VideoSourceConfiguration>
        <tt:VideoEncoderConfiguration token="VideoEncoder_{profile['token']}">
          <tt:Name>VideoEncoder</tt:Name>
          <tt:UseCount>1</tt:UseCount>
          <tt:Encoding>{profile['encoding']}</tt:Encoding>
          <tt:Resolution>
            <tt:Width>{profile['resolution']['width']}</tt:Width>
            <tt:Height>{profile['resolution']['height']}</tt:Height>
          </tt:Resolution>
          <tt:Quality>5</tt:Quality>
          <tt:RateControl>
            <tt:FrameRateLimit>{profile['fps']}</tt:FrameRateLimit>
            <tt:EncodingInterval>1</tt:EncodingInterval>
            <tt:BitrateLimit>4096</tt:BitrateLimit>
          </tt:RateControl>
          <tt:H264>
            <tt:GovLength>30</tt:GovLength>
            <tt:H264Profile>High</tt:H264Profile>
          </tt:H264>
          <tt:Multicast>
            <tt:Address>
              <tt:Type>IPv4</tt:Type>
              <tt:IPv4Address>0.0.0.0</tt:IPv4Address>
            </tt:Address>
            <tt:Port>0</tt:Port>
            <tt:TTL>1</tt:TTL>
            <tt:AutoStart>false</tt:AutoStart>
          </tt:Multicast>
          <tt:SessionTimeout>PT60S</tt:SessionTimeout>
        </tt:VideoEncoderConfiguration>
        <tt:PTZConfiguration token="PTZConfig_{profile['token']}">
          <tt:Name>PTZConfig</tt:Name>
          <tt:UseCount>1</tt:UseCount>
          <tt:NodeToken>PTZNode</tt:NodeToken>
          <tt:DefaultAbsolutePantTiltPositionSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:DefaultAbsolutePantTiltPositionSpace>
          <tt:DefaultAbsoluteZoomPositionSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:DefaultAbsoluteZoomPositionSpace>
          <tt:DefaultPTZTimeout>PT5S</tt:DefaultPTZTimeout>
          <tt:PanTiltLimits>
            <tt:Range>
              <tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:URI>
              <tt:XRange>
                <tt:Min>-1.0</tt:Min>
                <tt:Max>1.0</tt:Max>
              </tt:XRange>
              <tt:YRange>
                <tt:Min>-1.0</tt:Min>
                <tt:Max>1.0</tt:Max>
              </tt:YRange>
            </tt:Range>
          </tt:PanTiltLimits>
          <tt:ZoomLimits>
            <tt:Range>
              <tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:URI>
              <tt:XRange>
                <tt:Min>0.0</tt:Min>
                <tt:Max>1.0</tt:Max>
              </tt:XRange>
            </tt:Range>
          </tt:ZoomLimits>
        </tt:PTZConfiguration>
      </trt:Profile>
    </trt:GetProfileResponse>
    """
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetProfileResponse",
            response
        )


    def _handle_get_snapshot_uri(self, request: ET.Element) -> str:
        """
        Handle GetSnapshotUri request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        body = request.find('.//soap:Body', NS)
        if body is None:
            return XMLGenerator.generate_fault_response("Invalid SOAP request")

        get_snapshot_uri = body.find('.//trt:GetSnapshotUri', NS)
        if get_snapshot_uri is None:
            return XMLGenerator.generate_fault_response("Missing GetSnapshotUri element")

        profile_token_elem = get_snapshot_uri.find('.//trt:ProfileToken', NS)
        if profile_token_elem is None:
            return XMLGenerator.generate_fault_response("Missing ProfileToken")

        token = profile_token_elem.text
        auth_part = f"{self.username}:{self.password}@" if self.authentication_required else ""
        snapshot_url = f"http://{auth_part}{self.server_ip}:{self.onvif_port}/onvif/snapshot"

        response = f"""
<trt:GetSnapshotUriResponse>
  <trt:MediaUri>
    <tt:Uri>{snapshot_url}</tt:Uri>
    <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
    <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
    <tt:Timeout>PT60S</tt:Timeout>
  </trt:MediaUri>
</trt:GetSnapshotUriResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetSnapshotUriResponse",
            response
        )

    def _handle_get_video_encoder_configurations(self, request: ET.Element) -> str:
        """
        Handle GetVideoEncoderConfigurations request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        with self.profiles_lock:
            video_encoders = ""
            for profile_info in self.media_profiles:
                profile = profile_info.to_dict()
                video_encoders += f"""
<trt:Configurations token="VideoEncoder_{profile['token']}">
  <tt:Name>VideoEncoder</tt:Name>
  <tt:UseCount>1</tt:UseCount>
  <tt:Encoding>{profile['encoding']}</tt:Encoding>
  <tt:Resolution>
    <tt:Width>{profile['resolution']['width']}</tt:Width>
    <tt:Height>{profile['resolution']['height']}</tt:Height>
  </tt:Resolution>
  <tt:Quality>5</tt:Quality>
  <tt:RateControl>
    <tt:FrameRateLimit>{profile['fps']}</tt:FrameRateLimit>
    <tt:EncodingInterval>1</tt:EncodingInterval>
    <tt:BitrateLimit>4096</tt:BitrateLimit>
  </tt:RateControl>
  <tt:H264>
    <tt:GovLength>30</tt:GovLength>
    <tt:H264Profile>High</tt:H264Profile>
  </tt:H264>
  <tt:Multicast>
    <tt:Address>
      <tt:Type>IPv4</tt:Type>
      <tt:IPv4Address>0.0.0.0</tt:IPv4Address>
    </tt:Address>
    <tt:Port>0</tt:Port>
    <tt:TTL>1</tt:TTL>
    <tt:AutoStart>false</tt:AutoStart>
  </tt:Multicast>
  <tt:SessionTimeout>PT60S</tt:SessionTimeout>
</trt:Configurations>
"""
            response = f"""
<trt:GetVideoEncoderConfigurationsResponse>
{video_encoders}
</trt:GetVideoEncoderConfigurationsResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetVideoEncoderConfigurationsResponse",
            response
        )

    def _handle_get_video_source_configurations(self, request: ET.Element) -> str:
        """
        Handle GetVideoSourceConfigurations request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        with self.profiles_lock:
            video_sources = ""
            for profile_info in self.media_profiles:
                profile = profile_info.to_dict()
                video_sources += f"""
<trt:Configurations token="VideoSourceConfig_{profile['token']}">
  <tt:Name>VideoSourceConfig</tt:Name>
  <tt:UseCount>1</tt:UseCount>
  <tt:SourceToken>VideoSource</tt:SourceToken>
  <tt:Bounds height="{profile['resolution']['height']}" width="{profile['resolution']['width']}" y="0" x="0"/>
</trt:Configurations>
"""
            response = f"""
<trt:GetVideoSourceConfigurationsResponse>
{video_sources}
</trt:GetVideoSourceConfigurationsResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetVideoSourceConfigurationsResponse",
            response
        )

    def _handle_get_video_sources(self, request: ET.Element) -> str:
        """
        Handle GetVideoSources request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        # Use the highest resolution profile for video source info
        with self.profiles_lock:
            main_profile = self.media_profiles[0].to_dict()
            width = main_profile['resolution']['width']
            height = main_profile['resolution']['height']

            response = f"""
<trt:GetVideoSourcesResponse>
  <trt:VideoSources token="VideoSource">
    <tt:Framerate>30</tt:Framerate>
    <tt:Resolution>
      <tt:Width>{width}</tt:Width>
      <tt:Height>{height}</tt:Height>
    </tt:Resolution>
    <tt:Imaging>
      <tt:Brightness>50</tt:Brightness>
      <tt:ColorSaturation>50</tt:ColorSaturation>
      <tt:Contrast>50</tt:Contrast>
      <tt:Sharpness>50</tt:Sharpness>
    </tt:Imaging>
  </trt:VideoSources>
</trt:GetVideoSourcesResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetVideoSourcesResponse",
            response
        )

    def _handle_get_capabilities(self, request: ET.Element) -> str:
        """
        Handle GetCapabilities request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        response = f"""
<tds:GetCapabilitiesResponse>
  <tds:Capabilities>
    <tt:Device>
      <tt:XAddr>{self.device_service_url}</tt:XAddr>
      <tt:Network>
        <tt:IPFilter>false</tt:IPFilter>
        <tt:ZeroConfiguration>false</tt:ZeroConfiguration>
        <tt:IPVersion6>false</tt:IPVersion6>
        <tt:DynDNS>false</tt:DynDNS>
      </tt:Network>
      <tt:System>
        <tt:DiscoveryResolve>true</tt:DiscoveryResolve>
        <tt:DiscoveryBye>true</tt:DiscoveryBye>
        <tt:RemoteDiscovery>true</tt:RemoteDiscovery>
        <tt:SystemBackup>false</tt:SystemBackup>
        <tt:SystemLogging>false</tt:SystemLogging>
        <tt:FirmwareUpgrade>false</tt:FirmwareUpgrade>
        <tt:SupportedVersions>
          <tt:Major>1</tt:Major>
          <tt:Minor>0</tt:Minor>
        </tt:SupportedVersions>
      </tt:System>
      <tt:Security>
        <tt:TLS1.1>false</tt:TLS1.1>
        <tt:TLS1.2>false</tt:TLS1.2>
        <tt:OnboardKeyGeneration>false</tt:OnboardKeyGeneration>
        <tt:AccessPolicyConfig>false</tt:AccessPolicyConfig>
        <tt:DefaultAccessPolicy>false</tt:DefaultAccessPolicy>
        <tt:Dot1X>false</tt:Dot1X>
        <tt:RemoteUserHandling>false</tt:RemoteUserHandling>
        <tt:X.509Token>false</tt:X.509Token>
        <tt:SAMLToken>false</tt:SAMLToken>
        <tt:KerberosToken>false</tt:KerberosToken>
        <tt:UsernameToken>true</tt:UsernameToken>
        <tt:HttpDigest>false</tt:HttpDigest>
        <tt:RELToken>false</tt:RELToken>
      </tt:Security>
    </tt:Device>
    <tt:Media>
      <tt:XAddr>{self.media_service_url}</tt:XAddr>
      <tt:StreamingCapabilities>
        <tt:RTPMulticast>false</tt:RTPMulticast>
        <tt:RTP_TCP>true</tt:RTP_TCP>
        <tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
      </tt:StreamingCapabilities>
      <tt:SnapshotUri>true</tt:SnapshotUri>
      <tt:Rotation>false</tt:Rotation>
    </tt:Media>
  </tds:Capabilities>
</tds:GetCapabilitiesResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse",
            response
        )

    def _handle_get_video_source_configuration_options(self, request: ET.Element) -> str:
        """
        Handle GetVideoSourceConfigurationOptions request.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        logger.info("Processing GetVideoSourceConfigurationOptions request")

        try:
            # Get configuration token if specified
            config_token = None
            try:
                config_token_elem = request.find('.//trt:ConfigurationToken', NS)
                if config_token_elem is not None:
                    config_token = config_token_elem.text
                    logger.info(f"Configuration token specified: {config_token}")
            except Exception as e:
                logger.debug(f"Error getting configuration token: {e}")

            # Use main profile dimensions for max bounds
            with self.profiles_lock:
                main_profile = next((p for p in self.media_profiles if p.token == "profile1"), self.media_profiles[0])
                main_width = main_profile.width
                main_height = main_profile.height

            # Create a simple, standard-compliant response
            response = f"""
    <trt:GetVideoSourceConfigurationOptionsResponse>
      <trt:Options>
        <tt:BoundsRange>
          <tt:XRange>
            <tt:Min>0</tt:Min>
            <tt:Max>{main_width}</tt:Max>
          </tt:XRange>
          <tt:YRange>
            <tt:Min>0</tt:Min>
            <tt:Max>{main_height}</tt:Max>
          </tt:YRange>
          <tt:WidthRange>
            <tt:Min>320</tt:Min>
            <tt:Max>{main_width}</tt:Max>
          </tt:WidthRange>
          <tt:HeightRange>
            <tt:Min>240</tt:Min>
            <tt:Max>{main_height}</tt:Max>
          </tt:HeightRange>
        </tt:BoundsRange>
        <tt:VideoSourceTokensAvailable>VideoSource</tt:VideoSourceTokensAvailable>
      </trt:Options>
    </trt:GetVideoSourceConfigurationOptionsResponse>
    """
            logger.info("Sending GetVideoSourceConfigurationOptions response")
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetVideoSourceConfigurationOptionsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error in GetVideoSourceConfigurationOptions: {e}", exc_info=True)
            # Return a simple fallback response on error
            fallback_response = """
    <trt:GetVideoSourceConfigurationOptionsResponse>
      <trt:Options>
        <tt:BoundsRange>
          <tt:XRange>
            <tt:Min>0</tt:Min>
            <tt:Max>1920</tt:Max>
          </tt:XRange>
          <tt:YRange>
            <tt:Min>0</tt:Min>
            <tt:Max>1080</tt:Max>
          </tt:YRange>
          <tt:WidthRange>
            <tt:Min>320</tt:Min>
            <tt:Max>1920</tt:Max>
          </tt:WidthRange>
          <tt:HeightRange>
            <tt:Min>240</tt:Min>
            <tt:Max>1080</tt:Max>
          </tt:HeightRange>
        </tt:BoundsRange>
        <tt:VideoSourceTokensAvailable>VideoSource</tt:VideoSourceTokensAvailable>
      </trt:Options>
    </trt:GetVideoSourceConfigurationOptionsResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetVideoSourceConfigurationOptionsResponse",
                fallback_response
            )

    def _handle_get_service_capabilities(self, request: ET.Element, service_type: str) -> str:
        """
        Handle GetServiceCapabilities request for different services.

        Args:
            request: Request XML root
            service_type: Type of service ('device' or 'media')

        Returns:
            str: SOAP response XML
        """
        if service_type == 'device':
            response = """
<tds:GetServiceCapabilitiesResponse>
  <tds:Capabilities>
    <tds:Network IPFilter="false" ZeroConfiguration="false" IPVersion6="false" DynDNS="false" Dot11Configuration="false" HostnameFromDHCP="false" NTP="0" />
    <tds:Security TLS1.0="false" TLS1.1="false" TLS1.2="false" OnboardKeyGeneration="false" AccessPolicyConfig="false" DefaultAccessPolicy="false" Dot1X="false" RemoteUserHandling="false" X.509Token="false" SAMLToken="false" KerberosToken="false" UsernameToken="true" HttpDigest="false" RELToken="false" SupportedEAPMethods="0" MaxUsers="1" MaxUserNameLength="16" MaxPasswordLength="16" />
    <tds:System DiscoveryResolve="true" DiscoveryBye="true" RemoteDiscovery="true" SystemBackup="false" SystemLogging="false" FirmwareUpgrade="false" HttpFirmwareUpgrade="false" HttpSystemBackup="false" HttpSystemLogging="false" HttpSupportInformation="false" StorageConfiguration="false" />
  </tds:Capabilities>
</tds:GetServiceCapabilitiesResponse>
"""
            action = "http://www.onvif.org/ver10/device/wsdl/GetServiceCapabilitiesResponse"
        elif service_type == 'media':
            response = """
<trt:GetServiceCapabilitiesResponse>
  <trt:Capabilities SnapshotUri="true" Rotation="false" VideoSourceMode="false" OSD="false" TemporaryOSDText="false" EXICompression="false" RuleEngine="false" IVASupport="false" ProfileCapabilities="false" MaximumNumberOfProfiles="3" />
</trt:GetServiceCapabilitiesResponse>
"""
            action = "http://www.onvif.org/ver10/media/wsdl/GetServiceCapabilitiesResponse"
        else:
            return XMLGenerator.generate_fault_response(f"Unknown service type: {service_type}")

        return XMLGenerator.generate_soap_response(action, response)

    def _handle_get_scopes(self, request: ET.Element) -> str:
        """
        Handle GetScopes request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        response = f"""
<tds:GetScopesResponse>
  <tds:Scopes>
    <tds:ScopeDef>Fixed</tds:ScopeDef>
    <tds:ScopeItem>onvif://www.onvif.org/type/video_encoder</tds:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tds:ScopeDef>Fixed</tds:ScopeDef>
    <tds:ScopeItem>onvif://www.onvif.org/Profile/Streaming</tds:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tds:ScopeDef>Fixed</tds:ScopeDef>
    <tds:ScopeItem>onvif://www.onvif.org/name/YoLinkDashboard</tds:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tds:ScopeDef>Fixed</tds:ScopeDef>
    <tds:ScopeItem>onvif://www.onvif.org/location/Dashboard</tds:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tds:ScopeDef>Fixed</tds:ScopeDef>
    <tds:ScopeItem>onvif://www.onvif.org/hardware/{self.device_uuid}</tds:ScopeItem>
  </tds:Scopes>
</tds:GetScopesResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetScopesResponse",
            response
        )

    def _handle_get_system_date_and_time(self, request: ET.Element) -> str:
        """
        Handle GetSystemDateAndTime request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        now = datetime.datetime.utcnow()
        response = f"""
<tds:GetSystemDateAndTimeResponse>
  <tds:SystemDateAndTime>
    <tt:DateTimeType>Manual</tt:DateTimeType>
    <tt:DaylightSavings>false</tt:DaylightSavings>
    <tt:TimeZone>
      <tt:TZ>UTC</tt:TZ>
    </tt:TimeZone>
    <tt:UTCDateTime>
      <tt:Time>
        <tt:Hour>{now.hour}</tt:Hour>
        <tt:Minute>{now.minute}</tt:Minute>
        <tt:Second>{now.second}</tt:Second>
      </tt:Time>
      <tt:Date>
        <tt:Year>{now.year}</tt:Year>
        <tt:Month>{now.month}</tt:Month>
        <tt:Day>{now.day}</tt:Day>
      </tt:Date>
    </tt:UTCDateTime>
  </tds:SystemDateAndTime>
</tds:GetSystemDateAndTimeResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse",
            response
        )

    def _handle_get_hostname(self, request: ET.Element) -> str:
        """
        Handle GetHostname request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        response = """
<tds:GetHostnameResponse>
  <tds:HostnameInformation>
    <tt:FromDHCP>false</tt:FromDHCP>
    <tt:Name>YoLinkDashboard</tt:Name>
  </tds:HostnameInformation>
</tds:GetHostnameResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetHostnameResponse",
            response
        )

    def _handle_get_network_interfaces(self, request: ET.Element) -> str:
        """
        Handle GetNetworkInterfaces request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        response = f"""
<tds:GetNetworkInterfacesResponse>
  <tds:NetworkInterfaces token="eth0">
    <tt:Enabled>true</tt:Enabled>
    <tt:Info>
      <tt:Name>eth0</tt:Name>
      <tt:HwAddress>{MAC_ADDRESS}</tt:HwAddress>
    </tt:Info>
    <tt:IPv4>
      <tt:Enabled>true</tt:Enabled>
      <tt:Config>
        <tt:Manual>
          <tt:Address>{self.server_ip}</tt:Address>
          <tt:PrefixLength>24</tt:PrefixLength>
        </tt:Manual>
        <tt:DHCP>false</tt:DHCP>
      </tt:Config>
    </tt:IPv4>
  </tds:NetworkInterfaces>
</tds:GetNetworkInterfacesResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetNetworkInterfacesResponse",
            response
        )

    def _handle_get_network_protocols(self, request: ET.Element) -> str:
        """
        Handle GetNetworkProtocols request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        response = f"""
<tds:GetNetworkProtocolsResponse>
  <tds:NetworkProtocols>
    <tt:Name>HTTP</tt:Name>
    <tt:Enabled>true</tt:Enabled>
    <tt:Port>{self.onvif_port}</tt:Port>
  </tds:NetworkProtocols>
  <tds:NetworkProtocols>
    <tt:Name>RTSP</tt:Name>
    <tt:Enabled>true</tt:Enabled>
    <tt:Port>{self.rtsp_port}</tt:Port>
  </tds:NetworkProtocols>
</tds:GetNetworkProtocolsResponse>
"""
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetNetworkProtocolsResponse",
            response
        )

    def _generate_probe_match_response(self) -> str:
        """
        Generate a WS-Discovery ProbeMatch response.

        Returns:
            str: SOAP XML response
        """
        return f"""
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
    <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
  </s:Header>
  <s:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <a:EndpointReference>
          <a:Address>urn:uuid:{self.device_uuid}</a:Address>
        </a:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
        <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/YoLinkDashboard onvif://www.onvif.org/location/Dashboard onvif://www.onvif.org/hardware/{self.device_uuid}</d:Scopes>
        <d:XAddrs>{self.device_service_url} {self.media_service_url}</d:XAddrs>
        <d:MetadataVersion>1</d:MetadataVersion>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>
"""

    def _generate_bye_message(self) -> str:
        """
        Generate a WS-Discovery Bye message to announce device going offline.

        Returns:
            str: XML Bye message
        """
        return f"""
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye</a:Action>
    <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body>
    <d:Bye>
      <a:EndpointReference><a:Address>urn:uuid:{self.device_uuid}</a:Address></a:EndpointReference>
      <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
      <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/YoLinkDashboard onvif://www.onvif.org/location/Dashboard onvif://www.onvif.org/hardware/{self.device_uuid}</d:Scopes>
      <d:XAddrs>{self.device_service_url} {self.media_service_url}</d:XAddrs>
      <d:MetadataVersion>1</d:MetadataVersion>
    </d:Bye>
  </s:Body>
</s:Envelope>
"""

    def _cleanup(self) -> None:
        """Clean up resources when stopping the service."""
        logger.info("Cleaning up ONVIF service resources")
        if self.discovery_socket:
            try:
                self.discovery_socket.close()
            except Exception as e:
                logger.error(f"Error closing discovery socket: {e}")
            self.discovery_socket = None

        if self.http_server:
            try:
                self.http_server.shutdown()
                self.http_server.close_all_connections()
            except Exception as e:
                logger.error(f"Error shutting down HTTP server: {e}")
            self.http_server = None

        logger.info("ONVIF service resources cleaned up")

    def stop(self) -> None:
        """Stop the ONVIF service."""
        logger.info("Stopping ONVIF service")
        self.running = False
        self._cleanup()