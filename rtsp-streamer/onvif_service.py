"""
ONVIF service for device discovery and interaction.
Implements WS-Discovery and core ONVIF services with optimized resource usage.
Provides Profile S compliance with minimal PTZ support.
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
import traceback
import weakref
import ipaddress
import re
import random
from typing import Dict, Any, Optional, List, Tuple, Set, Callable
from urllib.parse import urlparse, parse_qs
from functools import lru_cache
from collections import defaultdict, deque
from onvif import generate_soap_response, generate_fault_response
from config import MAC_ADDRESS, generate_random_mac

# ONVIF XML namespaces - precomputed for efficiency
NAMESPACES = {
    'soap': 'http://www.w3.org/2003/05/soap-envelope',
    'wsa': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
    'wsd': 'http://schemas.xmlsoap.org/ws/2005/04/discovery',
    'tds': 'http://www.onvif.org/ver10/device/wsdl',
    'trt': 'http://www.onvif.org/ver10/media/wsdl',
    'tt': 'http://www.onvif.org/ver10/schema',
    'timg': 'http://www.onvif.org/ver20/imaging/wsdl',
    'tev': 'http://www.onvif.org/ver10/events/wsdl',
    'tptz': 'http://www.onvif.org/ver20/ptz/wsdl',
    'wsnt': 'http://docs.oasis-open.org/wsn/b-2',
    'wstop': 'http://docs.oasis-open.org/wsn/t-1',
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    's': 'http://www.w3.org/2003/05/soap-envelope',  # Sometimes used instead of soap
    'ter': 'http://www.onvif.org/ver10/error',  # Error namespace
    'tns1': 'http://www.onvif.org/ver10/topics'  # Topics namespace
}

# Register namespace prefixes for pretty XML output
for prefix, uri in NAMESPACES.items():
    ET.register_namespace(prefix, uri)

logging.basicConfig(
    level=logging.INFO,  # Set to DEBUG for more verbose output
    format='%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Create a logger instance
logger = logging.getLogger('OnvifService')

# Security utility functions
@lru_cache(maxsize=128)  # Cache digest computations to save CPU
def generate_nonce() -> str:
    """Generate a random nonce for digest authentication."""
    return base64.b64encode(os.urandom(16)).decode('utf-8')


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


def compute_digest_auth(username: str, password: str, realm: str, nonce: str, uri: str,
                       method: str, qop: Optional[str] = None,
                       cnonce: Optional[str] = None, nc: Optional[str] = None) -> str:
    """
    Compute HTTP Digest authentication response.

    Args:
        username: Username
        password: Password
        realm: Authentication realm
        nonce: Server nonce
        uri: Request URI
        method: HTTP method (e.g., GET, POST)
        qop: Quality of protection (auth, auth-int)
        cnonce: Client nonce (required if qop is provided)
        nc: Nonce count (required if qop is provided)

    Returns:
        Digest auth response string
    """
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

    if qop and cnonce and nc:
        response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    else:
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

    return response


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
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tev="http://www.onvif.org/ver10/events/wsdl"
               xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
               xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"
               xmlns:wstop="http://docs.oasis-open.org/wsn/t-1">
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


class OnvifEventEmitter:
    """
    ONVIF Event emitter for Push-Point and Pull-Point message delivery.
    Maintains a queue of events and allows subscriptions to events.
    """

    def __init__(self, max_queue_size: int = 100):
        """
        Initialize the event emitter.

        Args:
            max_queue_size: Maximum number of events to keep in queue
        """
        self.subscriptions = {}  # Dict from subscription ID to subscription details
        self.events_queue = deque(maxlen=max_queue_size)
        self.lock = threading.RLock()
        self.last_event_seq = 0

    def create_subscription(self, address: str, expires: int) -> Tuple[str, datetime.datetime]:
        """
        Create a new subscription.

        Args:
            address: Address to send events to (for push-point)
            expires: Time in seconds until subscription expires

        Returns:
            Tuple of (subscription_id, expiration_time)
        """
        with self.lock:
            subscription_id = f"sub_{uuid.uuid4()}"
            expiration_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires)

            self.subscriptions[subscription_id] = {
                'address': address,
                'expires': expiration_time,
                'last_sequence': self.last_event_seq,
                'topics': []  # No topic filtering for now
            }

            return subscription_id, expiration_time

    def renew_subscription(self, subscription_id: str, extends: int) -> Optional[datetime.datetime]:
        """
        Renew a subscription.

        Args:
            subscription_id: ID of subscription to renew
            extends: Additional time in seconds

        Returns:
            New expiration time or None if subscription not found
        """
        with self.lock:
            if subscription_id not in self.subscriptions:
                return None

            expiration_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=extends)
            self.subscriptions[subscription_id]['expires'] = expiration_time
            return expiration_time

    def unsubscribe(self, subscription_id: str) -> bool:
        """
        Remove a subscription.

        Args:
            subscription_id: ID of subscription to remove

        Returns:
            True if subscription was found and removed, False otherwise
        """
        with self.lock:
            if subscription_id in self.subscriptions:
                del self.subscriptions[subscription_id]
                return True
            return False

    def add_event(self, topic: str, source: str, data: Dict[str, Any]) -> int:
        """
        Add an event to the queue.

        Args:
            topic: Topic of the event
            source: Source of the event
            data: Event data as key-value pairs

        Returns:
            Sequence number of the added event
        """
        with self.lock:
            self.last_event_seq += 1
            seq = self.last_event_seq

            timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
            event = {
                'sequence': seq,
                'topic': topic,
                'source': source,
                'timestamp': timestamp,
                'data': data
            }

            self.events_queue.append(event)
            return seq

    def pull_events(self, subscription_id: str, timeout: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        """
        Pull events for a subscription.

        Args:
            subscription_id: ID of subscription
            timeout: Maximum time to wait for events in seconds

        Returns:
            Tuple of (events_list, current_sequence)
        """
        with self.lock:
            if subscription_id not in self.subscriptions:
                return [], 0

            subscription = self.subscriptions[subscription_id]
            last_sequence = subscription['last_sequence']

            # Get events since last sequence
            events = []
            for event in self.events_queue:
                if event['sequence'] > last_sequence:
                    events.append(event)

            # Update subscription's last sequence
            if events:
                subscription['last_sequence'] = events[-1]['sequence']

            return events, self.last_event_seq

    def cleanup_expired_subscriptions(self) -> List[str]:
        """
        Remove expired subscriptions.

        Returns:
            List of removed subscription IDs
        """
        with self.lock:
            now = datetime.datetime.utcnow()
            expired = []

            for sub_id, sub in list(self.subscriptions.items()):
                if sub['expires'] < now:
                    expired.append(sub_id)
                    del self.subscriptions[sub_id]

            return expired

    def get_subscription_info(self, subscription_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a subscription.

        Args:
            subscription_id: ID of subscription

        Returns:
            Subscription details dict or None if not found
        """
        with self.lock:
            return self.subscriptions.get(subscription_id)


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
        self.auth_nonce = None
        self.auth_realm = "ONVIF"
        super().__init__(*args, **kwargs)

    def do_POST(self):
        """Handle ONVIF SOAP POST requests."""
        try:
            # Log request details at debug level
            logger.debug(f"Received POST request to {self.path} from {self.client_address[0]}")

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

            # Check authentication before processing request
            auth_result = self._check_authentication(soap_request)
            if not auth_result:
                if self.service.digest_auth_enabled:
                    # For digest auth, send a nonce challenge
                    self.auth_nonce = base64.b64encode(os.urandom(16)).hex()
                    self.send_response(401)
                    self.send_header('WWW-Authenticate',
                                    f'Digest realm="{self.auth_realm}", '
                                    f'nonce="{self.auth_nonce}", '
                                    f'qop="auth", algorithm=MD5')
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"Digest authentication required")
                else:
                    # For basic auth, send a basic auth challenge
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="ONVIF"')
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"Authentication required")
                return

            # Process the request based on the path
            service_path = self.path.lower()
            response = ""

            if '/onvif/device_service' in service_path:
                response = self.service.handle_device_service(soap_request)
            elif '/onvif/media_service' in service_path:
                response = self.service.handle_media_service(soap_request)
            elif '/onvif/events_service' in service_path or '/onvif/event_service' in service_path:
                response = self.service.handle_events_service(soap_request)
            elif '/onvif/imaging_service' in service_path:
                response = self.service.handle_imaging_service(soap_request)
            elif '/onvif/ptz_service' in service_path:
                response = self.service.handle_ptz_service(soap_request)
            elif '/onvif/snapshot' in service_path:
                self._handle_snapshot_request()
                return
            else:
                self.send_error(404, "Service not found")
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/soap+xml; charset=utf-8')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))

        except Exception as e:
            logger.error(f"Request processing error: {e}", exc_info=True)
            self.send_error(500, "Internal server error")

    def _handle_snapshot_request(self):
        """Handle snapshot requests by returning a placeholder image."""
        try:
            # Get profile token from query string if available
            query = urlparse(self.path).query
            query_params = parse_qs(query)
            token = query_params.get('token', ['profile1'])[0]

            # For this implementation, generate a simple placeholder image
            # In a real implementation, you would capture a frame from the video stream

            # Generate a gray placeholder image with timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Get dimensions from the profile
            profile = None
            for p in self.service.media_profiles:
                if p.token == token:
                    profile = p
                    break

            width = 320
            height = 240
            if profile:
                width = profile.width
                height = profile.height

            # Generate a simple BMP image (minimal headers + raw data)
            # This is a very simplified implementation - a real one would capture actual frames

            # For simplicity in this example, we'll send a tiny 1x1 transparent GIF
            # In a real implementation, you would generate a proper image or grab a frame
            transparent_gif = base64.b64decode(
                "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

            self.send_response(200)
            self.send_header('Content-Type', 'image/gif')
            self.send_header('Content-Length', str(len(transparent_gif)))
            self.end_headers()
            self.wfile.write(transparent_gif)

        except Exception as e:
            logger.error(f"Error handling snapshot request: {e}", exc_info=True)
            self.send_error(500, "Internal server error generating snapshot")

    def _check_authentication(self, soap_request: str) -> bool:
        """
        Enhanced authentication handler with support for Basic and Digest auth.

        Args:
            soap_request: The SOAP request XML

        Returns:
            bool: True if authentication is valid or not required
        """
        # Skip authentication if not required
        if not self.service.authentication_required:
            logger.debug("Authentication not required, accepting request")
            return True

        # Log current settings for diagnostics
        logger.debug(f"ONVIF Auth Settings - Required: {self.service.authentication_required}, "
                    f"Username: {self.service.username}, Digest Auth: {self.service.digest_auth_enabled}")

        # CHECK 1: Basic Authentication in header
        auth_header = self.headers.get('Authorization')
        if auth_header:
            if self.service.digest_auth_enabled and auth_header.startswith('Digest '):
                # Parse digest auth header
                try:
                    # Extract digest auth parameters
                    auth_parts = re.findall(r'(\w+)=(?:"([^"]+)"|([^,]+))', auth_header)
                    auth_params = {k: v[0] or v[1] for k, v, _ in auth_parts}

                    # Verify username
                    if auth_params.get('username') != self.service.username:
                        logger.warning(f"Digest auth username mismatch: '{auth_params.get('username')}'")
                        return False

                    # Compute expected response
                    expected_response = compute_digest_auth(
                        username=self.service.username,
                        password=self.service.password,
                        realm=auth_params.get('realm', self.auth_realm),
                        nonce=auth_params.get('nonce', ''),
                        uri=auth_params.get('uri', self.path),
                        method='POST',
                        qop=auth_params.get('qop'),
                        cnonce=auth_params.get('cnonce'),
                        nc=auth_params.get('nc')
                    )

                    # Compare with client response
                    if auth_params.get('response') == expected_response:
                        logger.debug("Digest authentication successful")
                        return True
                    else:
                        logger.warning("Digest authentication failed - invalid response")
                except Exception as e:
                    logger.warning(f"Error parsing digest auth: {e}")

            elif auth_header.startswith('Basic '):
                try:
                    auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    username, password = auth_decoded.split(':', 1)
                    logger.debug(f"Basic auth attempt with username: {username}")

                    # Compare credentials
                    if username == self.service.username and password == self.service.password:
                        logger.debug("Basic auth successful")
                        return True
                    else:
                        logger.warning(f"Basic auth failed: Username mismatch or invalid password")
                except Exception as e:
                    logger.warning(f"Error parsing Basic auth: {e}")

        # CHECK 2: WS-Security UsernameToken in SOAP body
        try:
            if "<Security>" in soap_request and "<UsernameToken>" in soap_request:
                # Extract username
                username_match = re.search(r'<Username[^>]*>(.*?)</Username>', soap_request)
                if not username_match:
                    logger.warning("No Username element found in UsernameToken")
                    return False

                soap_username = username_match.group(1)

                # Check username
                if soap_username != self.service.username:
                    logger.warning(f"WS-Security username mismatch: '{soap_username}'")
                    return False

                # Check if password is provided as clear text
                password_match = re.search(r'<Password[^>]*>(.*?)</Password>', soap_request)
                if password_match:
                    soap_password = password_match.group(1)

                    # For simple text password
                    if soap_password == self.service.password:
                        logger.debug("WS-Security password match")
                        return True

                # Check for digest authentication
                nonce_match = re.search(r'<Nonce[^>]*>(.*?)</Nonce>', soap_request)
                created_match = re.search(r'<Created[^>]*>(.*?)</Created>', soap_request)
                password_digest_match = re.search(r'<Password[^>]*Type="[^"]*#PasswordDigest"[^>]*>(.*?)</Password>',
                                               soap_request)

                if nonce_match and created_match and password_digest_match:
                    nonce = nonce_match.group(1)
                    created = created_match.group(1)
                    password_digest = password_digest_match.group(1)

                    # Compute expected digest
                    expected_digest = compute_password_digest(nonce, created, self.service.password)

                    if password_digest == expected_digest:
                        logger.debug("WS-Security password digest match")
                        return True
                    else:
                        logger.warning("WS-Security password digest mismatch")
        except Exception as e:
            logger.warning(f"Error checking WS-Security auth: {e}")

        # Authentication failed
        logger.warning("Authentication failed - all methods tried")
        return False

    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"{self.address_string()} - {format % args}")

    def do_GET(self):
        """Handle GET requests, mainly for snapshot retrieval."""
        if '/onvif/snapshot' in self.path.lower():
            self._handle_snapshot_request()
        else:
            self.send_error(405, "Method Not Allowed")


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
    Enhanced for Profile S compliance.
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
        self.onvif_port = int(config.get("onvif_port", 8000))
        self.rtsp_port = int(config.get("rtsp_port", 554))
        self.stream_name = config.get("stream_name", "yolink-dashboard")

        # Authentication settings
        self.authentication_required = config.get("onvif_auth_required", True)
        self.digest_auth_enabled = config.get("onvif_digest_auth", True)
        self.username = config.get("onvif_username", "admin")
        self.password = config.get("onvif_password", "123456")

        # Device identification
        self.device_uuid = str(uuid.uuid4())
        self.mac_address = os.getenv("MAC_ADDRESS")
        if not self.mac_address:
            self.mac_address = generate_random_mac()
        self.hardware_id = config.get("hardware_id", f"HW-{self.device_uuid[:8]}")

        # Device information
        self.device_info = {
            "Manufacturer": config.get("manufacturer", "Industrial Camera Systems"),
            "Model": config.get("model", "Dashboard-RTSP"),
            "FirmwareVersion": config.get("firmware_version", "1.0.1"),
            "SerialNumber": self.device_uuid,
            "HardwareId": self.hardware_id
        }

        # Service URLs
        self.device_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/device_service"
        self.media_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/media_service"
        self.events_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/events_service"
        self.imaging_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/imaging_service"
        self.ptz_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/ptz_service"

        # Server and socket objects
        self.http_server = None
        self.discovery_socket = None
        self.discovery_thread = None
        self.event_thread = None
        self.last_announce_time = 0
        self.announce_interval = 300  # 5 minutes between announcements

        # Profile and event related objects
        self.profiles_lock = threading.RLock()
        self.media_profiles = []
        self.event_emitter = OnvifEventEmitter()
        self.imaging_settings = {
            'brightness': 50,
            'contrast': 50,
            'saturation': 50,
            'sharpness': 50,
            'exposure': {
                'mode': 'AUTO',
                'priority': 'FrameRate',
                'minExposureTime': 1000,
                'maxExposureTime': 33000
            },
            'focus': {
                'mode': 'AUTO',
                'defaultSpeed': 1.0,
                'nearLimit': 0.1,
                'farLimit': 0.0
            },
            'whiteBalance': {
                'mode': 'AUTO',
                'cbGain': 1.0,
                'crGain': 1.0
            }
        }

        # PTZ status (minimal)
        self.ptz_status = {
            'position': {
                'x': 0.0,  # Pan
                'y': 0.0,  # Tilt
                'z': 0.0   # Zoom
            },
            'moveStatus': {
                'panTilt': 'IDLE',
                'zoom': 'IDLE'
            },
            'error': '',
            'utcTime': ''
        }

        # Set up profiles based on configuration
        self._setup_profiles()

        # Callbacks for profiles
        self.profile_callbacks = {}
        self.running = True
        self.lock = threading.RLock()

    def _setup_profiles(self):
        """Set up media profiles based on configuration."""
        # Main profile - highest quality
        self.media_profiles.append(
            ProfileInfo(
                token="profile1",
                name="Dashboard Main Stream",
                width=self.config.get("width", 1920),
                height=self.config.get("height", 1080),
                fps=self.config.get("frame_rate", 6),
                sensors_per_page=self.config.get("sensors_per_page", 20)
            )
        )

        # Secondary profile - medium quality
        self.media_profiles.append(
            ProfileInfo(
                token="profile2",
                name="Dashboard Low Stream",
                width=self.config.get("low_res_width", self.config.get("width", 1920) // 2),
                height=self.config.get("low_res_height", self.config.get("height", 1080) // 2),
                fps=self.config.get("low_res_fps", min(self.config.get("frame_rate", 6), 4)),
                sensors_per_page=self.config.get("low_res_sensors_per_page", 6)
            )
        )

        # Mobile profile - lowest quality
        self.media_profiles.append(
            ProfileInfo(
                token="profile3",
                name="Dashboard Mobile Stream",
                width=self.config.get("mobile_width", self.config.get("width", 1920) // 4),
                height=self.config.get("mobile_height", self.config.get("height", 1080) // 4),
                fps=self.config.get("mobile_fps", 2),
                sensors_per_page=self.config.get("mobile_sensors_per_page", 4)
            )
        )

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
            # Start HTTP server for ONVIF services
            self._start_http_server()

            # Start WS-Discovery for device announcement
            self._start_discovery_thread()

            # Start event emitter thread
            self._start_event_thread()

            # Add initial system events
            self._generate_initial_events()

            while self.running:
                time.sleep(1)
        except Exception as e:
            logger.error(f"Error in ONVIF service: {e}", exc_info=True)
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

    def _start_event_thread(self) -> None:
        """Start the thread that generates events and cleans up expired subscriptions."""
        self.event_thread = threading.Thread(
            target=self._event_loop,
            daemon=True,
            name="onvif-events"
        )
        self.event_thread.start()
        logger.info("ONVIF events service started")

    def _generate_initial_events(self) -> None:
        """Generate initial events when the service starts."""
        # Add device-related events
        self.event_emitter.add_event(
            topic="tns1:Device/tns1:Trigger/tns1:Status",
            source="Device",
            data={
                "State": True,
                "Token": "Device"
            }
        )

        # Add stream-related events
        for profile in self.media_profiles:
            self.event_emitter.add_event(
                topic="tns1:VideoSource/tns1:VideoStream/tns1:Status",
                source=f"Profile_{profile.token}",
                data={
                    "State": True,
                    "Token": profile.token
                }
            )

    def _event_loop(self) -> None:
        """Thread function that generates periodic events and cleans up subscriptions."""
        try:
            while self.running:
                # Clean up expired subscriptions
                expired = self.event_emitter.cleanup_expired_subscriptions()
                if expired:
                    logger.info(f"Removed {len(expired)} expired subscriptions: {expired}")

                # Generate periodic events
                if random.random() < 0.05:  # 5% chance each iteration
                    topic = random.choice([
                        "tns1:Device/tns1:Trigger/tns1:DigitalInput",
                        "tns1:VideoSource/tns1:VideoMotion",
                        "tns1:VideoAnalytics/tns1:Motion/tns1:Motion"
                    ])

                    profile = random.choice(self.media_profiles)

                    if "DigitalInput" in topic:
                        self.event_emitter.add_event(
                            topic=topic,
                            source="Sensor1",
                            data={
                                "State": random.choice([True, False]),
                                "Token": "DI1"
                            }
                        )
                    elif "VideoMotion" in topic:
                        self.event_emitter.add_event(
                            topic=topic,
                            source=f"VideoSource_{profile.token}",
                            data={
                                "State": random.random() > 0.5,
                                "Token": profile.token
                            }
                        )
                    elif "VideoAnalytics" in topic:
                        self.event_emitter.add_event(
                            topic=topic,
                            source=f"Analytics_{profile.token}",
                            data={
                                "Value": random.random(),
                                "Rule": "Motion1",
                                "Token": profile.token
                            }
                        )

                # Sleep for a bit
                time.sleep(10)

        except Exception as e:
            logger.error(f"Error in event thread: {e}")
            if self.running:
                # Restart the thread if it crashes
                time.sleep(5)
                self._start_event_thread()

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
      <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/{self.device_info['Model']} onvif://www.onvif.org/location/Dashboard onvif://www.onvif.org/hardware/{self.device_uuid}</d:Scopes>
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

            body = root.find('.//soap:Body', NAMESPACES)
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

            # Define service actions that might be sent to device endpoint
            media_actions = {
                'GetProfiles', 'GetProfile', 'GetStreamUri', 'GetSnapshotUri',
                'GetVideoEncoderConfigurations', 'GetVideoSources', 'GetVideoSourceConfigurations',
                'GetVideoSourceConfigurationOptions', 'GetAudioSourceConfigurations',
                'GetCompatibleVideoEncoderConfigurations', 'GetVideoEncoderConfigurationOptions'
            }

            events_actions = {
                'GetEventProperties', 'CreatePullPointSubscription', 'PullMessages',
                'Subscribe', 'Unsubscribe', 'Renew', 'SetSynchronizationPoint'
            }

            imaging_actions = {
                'GetImagingSettings', 'SetImagingSettings', 'GetOptions', 'GetMoveOptions',
                'Move', 'Stop', 'GetStatus', 'GetServiceCapabilities'
            }

            ptz_actions = {
                'GetConfigurations', 'GetConfiguration', 'GetConfigurationOptions',
                'GetStatus', 'GetPresets', 'GotoPreset', 'ContinuousMove', 'RelativeMove',
                'AbsoluteMove', 'Stop', 'GetServiceCapabilities'
            }

            # If this is a media action, redirect to the media service handler
            if local_name in media_actions:
                logger.info(f"Redirecting media action '{local_name}' from device service to media service")
                return self.handle_media_service(soap_request)

            # If this is an events action, redirect to the events service handler
            if local_name in events_actions:
                logger.info(f"Redirecting events action '{local_name}' from device service to events service")
                return self.handle_events_service(soap_request)

            # If this is an imaging action, redirect to the imaging service handler
            if local_name in imaging_actions:
                logger.info(f"Redirecting imaging action '{local_name}' from device service to imaging service")
                return self.handle_imaging_service(soap_request)

            # If this is a PTZ action, redirect to the PTZ service handler
            if local_name in ptz_actions:
                logger.info(f"Redirecting PTZ action '{local_name}' from device service to PTZ service")
                return self.handle_ptz_service(soap_request)

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
                'GetNetworkProtocols': self._handle_get_network_protocols,
                'GetDiscoveryMode': self._handle_get_discovery_mode,
                'GetDNS': self._handle_get_dns,
                'GetDynamicDNS': self._handle_get_dynamic_dns,
                'GetUsers': self._handle_get_users,
                'GetWsdlUrl': self._handle_get_wsdl_url,
                'GetSystemLog': self._handle_get_system_log,
                'GetSystemSupportInformation': self._handle_get_system_support_information,
                'GetSystemBackup': self._handle_get_system_backup,
                'SystemReboot': self._handle_system_reboot,
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
            logger.error(f"Error handling device service request: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Internal error: {str(e)}")

    def _handle_get_device_information(self, request: ET.Element) -> str:
        """
        Handle GetDeviceInformation request.
        Returns device information such as manufacturer, model, etc.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Generate the response using device_info
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
        except Exception as e:
            logger.error(f"Error handling GetDeviceInformation: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting device information: {str(e)}")

    def _handle_get_services(self, request: ET.Element) -> str:
        """
        Handle GetServices request.
        Returns a list of available ONVIF services with their URLs and versions.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Check if IncludeCapability is present and set to true
            include_capability = False
            get_services = request.find('.//tds:GetServices', NAMESPACES)
            if get_services is not None:
                capability_elem = get_services.find('.//tds:IncludeCapability', NAMESPACES)
                if capability_elem is not None and capability_elem.text.lower() == 'true':
                    include_capability = True

            # Define the services supported by this device
            services_xml = f"""
    <tds:Service>
      <tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>
      <tds:XAddr>{self.device_service_url}</tds:XAddr>
      <tds:Version>
        <tt:Major>2</tt:Major>
        <tt:Minor>6</tt:Minor>
      </tds:Version>
    </tds:Service>
    <tds:Service>
      <tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>
      <tds:XAddr>{self.media_service_url}</tds:XAddr>
      <tds:Version>
        <tt:Major>2</tt:Major>
        <tt:Minor>6</tt:Minor>
      </tds:Version>
    </tds:Service>
    <tds:Service>
      <tds:Namespace>http://www.onvif.org/ver10/events/wsdl</tds:Namespace>
      <tds:XAddr>{self.events_service_url}</tds:XAddr>
      <tds:Version>
        <tt:Major>2</tt:Major>
        <tt:Minor>6</tt:Minor>
      </tds:Version>
    </tds:Service>
    <tds:Service>
      <tds:Namespace>http://www.onvif.org/ver20/imaging/wsdl</tds:Namespace>
      <tds:XAddr>{self.imaging_service_url}</tds:XAddr>
      <tds:Version>
        <tt:Major>2</tt:Major>
        <tt:Minor>6</tt:Minor>
      </tds:Version>
    </tds:Service>
    <tds:Service>
      <tds:Namespace>http://www.onvif.org/ver20/ptz/wsdl</tds:Namespace>
      <tds:XAddr>{self.ptz_service_url}</tds:XAddr>
      <tds:Version>
        <tt:Major>2</tt:Major>
        <tt:Minor>6</tt:Minor>
      </tds:Version>
    </tds:Service>
    """

            # Optionally include capabilities if requested (simplified for now)
            if include_capability:
                services_xml = services_xml.replace(
                    "</tds:Service>",
                    f"""<tds:Capabilities><!-- Simplified capabilities -->
        </tds:Capabilities></tds:Service>"""
                )

            response = f"""
    <tds:GetServicesResponse>
      {services_xml}
    </tds:GetServicesResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetServicesResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetServices: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting services: {str(e)}")

    def _handle_get_capabilities(self, request: ET.Element) -> str:
        """
        Handle GetCapabilities request.
        Returns the capabilities of the ONVIF device.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Extract category if specified, default to 'All'
            get_capabilities = request.find('.//tds:GetCapabilities', NAMESPACES)
            category = 'All'
            if get_capabilities is not None:
                category_elem = get_capabilities.find('.//tds:Category', NAMESPACES)
                if category_elem is not None:
                    category = category_elem.text

            # Define capabilities based on supported services
            capabilities_xml = ""

            if category in ['All', 'Device']:
                capabilities_xml += """
        <tt:Device>
          <tt:Network>
            <tt:IPFilter>false</tt:IPFilter>
            <tt:ZeroConfiguration>false</tt:ZeroConfiguration>
            <tt:IPVersion6>false</tt:IPVersion6>
            <tt:DynDNS>false</tt:DynDNS>
            <tt:Dot11Configuration>false</tt:Dot11Configuration>
            <tt:HostnameFromDHCP>false</tt:HostnameFromDHCP>
            <tt:NTP>0</tt:NTP>
          </tt:Network>
          <tt:System>
            <tt:DiscoveryResolve>true</tt:DiscoveryResolve>
            <tt:DiscoveryBye>true</tt:DiscoveryBye>
            <tt:RemoteDiscovery>true</tt:RemoteDiscovery>
            <tt:SystemBackup>false</tt:SystemBackup>
            <tt:SystemLogging>false</tt:SystemLogging>
            <tt:FirmwareUpgrade>false</tt:FirmwareUpgrade>
            <tt:HttpFirmwareUpgrade>false</tt:HttpFirmwareUpgrade>
            <tt:HttpSystemBackup>false</tt:HttpSystemBackup>
            <tt:HttpSystemLogging>false</tt:HttpSystemLogging>
            <tt:HttpSupportInformation>false</tt:HttpSupportInformation>
          </tt:System>
          <tt:IO>
            <tt:InputConnectors>0</tt:InputConnectors>
            <tt:RelayOutputs>0</tt:RelayOutputs>
          </tt:IO>
          <tt:Security>
            <tt:TLS1.0>false</tt:TLS1.0>
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
            <tt:HttpDigest>true</tt:HttpDigest>
            <tt:RELToken>false</tt:RELToken>
          </tt:Security>
        </tt:Device>
    """

            if category in ['All', 'Media']:
                capabilities_xml += """
        <tt:Media>
          <tt:StreamingCapabilities>
            <tt:RTPMulticast>false</tt:RTPMulticast>
            <tt:RTP_TCP>true</tt:RTP_TCP>
            <tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
          </tt:StreamingCapabilities>
          <tt:ProfileCapabilities>
            <tt:MaximumNumberOfProfiles>3</tt:MaximumNumberOfProfiles>
          </tt:ProfileCapabilities>
        </tt:Media>
    """

            if category in ['All', 'Events']:
                capabilities_xml += """
        <tt:Events>
          <tt:WSSubscriptionPolicySupport>false</tt:WSSubscriptionPolicySupport>
          <tt:WSPullPointSupport>true</tt:WSPullPointSupport>
          <tt:WSPausableSubscriptionManagerInterfaceSupport>false</tt:WSPausableSubscriptionManagerInterfaceSupport>
        </tt:Events>
    """

            if category in ['All', 'Imaging']:
                capabilities_xml += """
        <tt:Imaging>
          <tt:ImageStabilization>false</tt:ImageStabilization>
        </tt:Imaging>
    """

            if category in ['All', 'PTZ']:
                capabilities_xml += """
        <tt:PTZ>
          <tt:EFlip>false</tt:EFlip>
          <tt:Reverse>false</tt:Reverse>
          <tt:GetCompatibleConfigurations>true</tt:GetCompatibleConfigurations>
          <tt:MoveStatus>true</tt:MoveStatus>
          <tt:StatusPosition>true</tt:StatusPosition>
        </tt:PTZ>
    """

            response = f"""
    <tds:GetCapabilitiesResponse>
      <tds:Capabilities>
        {capabilities_xml}
      </tds:Capabilities>
    </tds:GetCapabilitiesResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetCapabilities: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting capabilities: {str(e)}")

    def _handle_get_scopes(self, request: ET.Element) -> str:
        """
        Handle GetScopes request.
        Returns the scope parameters of the ONVIF device.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Define scopes based on device configuration
            scopes_xml = f"""
        <tds:Scopes>
          <tt:ScopeDef>Fixed</tt:ScopeDef>
          <tt:ScopeItem>onvif://www.onvif.org/type/video_encoder</tt:ScopeItem>
        </tds:Scopes>
        <tds:Scopes>
          <tt:ScopeDef>Fixed</tt:ScopeDef>
          <tt:ScopeItem>onvif://www.onvif.org/Profile/Streaming</tt:ScopeItem>
        </tds:Scopes>
        <tds:Scopes>
          <tt:ScopeDef>Fixed</tt:ScopeDef>
          <tt:ScopeItem>onvif://www.onvif.org/name/{self.device_info['Model']}</tt:ScopeItem>
        </tds:Scopes>
        <tds:Scopes>
          <tt:ScopeDef>Fixed</tt:ScopeDef>
          <tt:ScopeItem>onvif://www.onvif.org/location/Dashboard</tt:ScopeItem>
        </tds:Scopes>
        <tds:Scopes>
          <tt:ScopeDef>Fixed</tt:ScopeDef>
          <tt:ScopeItem>onvif://www.onvif.org/hardware/{self.device_uuid}</tt:ScopeItem>
        </tds:Scopes>
    """

            response = f"""
    <tds:GetScopesResponse>
      {scopes_xml}
    </tds:GetScopesResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetScopesResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetScopes: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting scopes: {str(e)}")

    def _handle_get_system_date_and_time(self, request: ET.Element) -> str:
        """
        Handle GetSystemDateAndTime request.
        Returns the current system date and time of the ONVIF device in UTC.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Get current UTC time
            utc_now = datetime.datetime.utcnow()
            utc_time_str = utc_now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # Since this is a simple implementation, assume no local time or DST
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
            <tt:Hour>{utc_now.hour}</tt:Hour>
            <tt:Minute>{utc_now.minute}</tt:Minute>
            <tt:Second>{utc_now.second}</tt:Second>
          </tt:Time>
          <tt:Date>
            <tt:Year>{utc_now.year}</tt:Year>
            <tt:Month>{utc_now.month}</tt:Month>
            <tt:Day>{utc_now.day}</tt:Day>
          </tt:Date>
        </tt:UTCDateTime>
      </tds:SystemDateAndTime>
    </tds:GetSystemDateAndTimeResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetSystemDateAndTime: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting system date and time: {str(e)}")

    def _handle_get_network_interfaces(self, request: ET.Element) -> str:
        """
        Handle GetNetworkInterfaces request.
        Returns information about the device's network interfaces.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Simple single-interface response using server_ip
            response = f"""
    <tds:GetNetworkInterfacesResponse>
      <tds:NetworkInterfaces token="eth0">
        <tt:Enabled>true</tt:Enabled>
        <tt:Info>
          <tt:Name>eth0</tt:Name>
          <tt:HwAddress>{self.mac_address}</tt:HwAddress>
          <tt:MTU>1500</tt:MTU>
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
        except Exception as e:
            logger.error(f"Error handling GetNetworkInterfaces: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting network interfaces: {str(e)}")

    def _handle_get_network_protocols(self, request: ET.Element) -> str:
        """
        Handle GetNetworkProtocols request.
        Returns the supported network protocols and their ports.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
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
        except Exception as e:
            logger.error(f"Error handling GetNetworkProtocols: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting network protocols: {str(e)}")

    def _handle_get_profile(self, request: ET.Element) -> str:
        """
        Handle GetProfile request.
        Returns a specific media profile based on the provided token.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Extract profile token from the request
            get_profile = request.find('.//trt:GetProfile', NAMESPACES)
            if get_profile is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetProfile element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = get_profile.find('.//trt:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Find the matching profile
            profile = None
            with self.profiles_lock:
                for p in self.media_profiles:
                    if p.token == profile_token:
                        profile = p
                        break

            if profile is None:
                return XMLGenerator.generate_fault_response(
                    f"Profile {profile_token} not found",
                    "ter:InvalidArgVal"
                )

            # Generate profile XML (simplified from _handle_get_profiles)
            profile_dict = profile.to_dict()
            width = profile_dict['resolution']['width']
            height = profile_dict['resolution']['height']
            response = f"""
    <trt:GetProfileResponse>
      <trt:Profile fixed="true" token="{profile.token}">
        <tt:Name>{profile.name}</tt:Name>
        <tt:VideoSourceConfiguration token="VideoSourceConfig_{profile.token}">
          <tt:Name>VideoSourceConfig_{profile.token}</tt:Name>
          <tt:UseCount>1</tt:UseCount>
          <tt:SourceToken>VideoSource</tt:SourceToken>
          <tt:Bounds height="{height}" width="{width}" y="0" x="0"/>
        </tt:VideoSourceConfiguration>
        <tt:VideoEncoderConfiguration token="VideoEncoder_{profile.token}">
          <tt:Name>VideoEncoder_{profile.token}</tt:Name>
          <tt:UseCount>1</tt:UseCount>
          <tt:Encoding>H264</tt:Encoding>
          <tt:Resolution>
            <tt:Width>{width}</tt:Width>
            <tt:Height>{height}</tt:Height>
          </tt:Resolution>
          <tt:Quality>5</tt:Quality>
          <tt:RateControl>
            <tt:FrameRateLimit>{profile.fps}</tt:FrameRateLimit>
            <tt:EncodingInterval>1</tt:EncodingInterval>
            <tt:BitrateLimit>4000</tt:BitrateLimit>
          </tt:RateControl>
          <tt:H264>
            <tt:GovLength>30</tt:GovLength>
            <tt:H264Profile>High</tt:H264Profile>
          </tt:H264>
        </tt:VideoEncoderConfiguration>
      </trt:Profile>
    </trt:GetProfileResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetProfileResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetProfile: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting profile: {str(e)}")

    def _handle_get_snapshot_uri(self, request: ET.Element) -> str:
        """
        Handle GetSnapshotUri request.
        Returns a URI for retrieving a snapshot for a specific profile.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Extract profile token from the request
            get_snapshot_uri = request.find('.//trt:GetSnapshotUri', NAMESPACES)
            if get_snapshot_uri is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetSnapshotUri element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = get_snapshot_uri.find('.//trt:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Validate profile exists
            profile = None
            with self.profiles_lock:
                for p in self.media_profiles:
                    if p.token == profile_token:
                        profile = p
                        break

            if profile is None:
                return XMLGenerator.generate_fault_response(
                    f"Profile {profile_token} not found",
                    "ter:InvalidArgVal"
                )

            # Construct snapshot URI (matches your existing /onvif/snapshot endpoint)
            snapshot_uri = f"http://{self.server_ip}:{self.onvif_port}/onvif/snapshot?token={profile_token}"
            response = f"""
    <trt:GetSnapshotUriResponse>
      <trt:MediaUri>
        <tt:Uri>{snapshot_uri}</tt:Uri>
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
        except Exception as e:
            logger.error(f"Error handling GetSnapshotUri: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting snapshot URI: {str(e)}")

    def _handle_get_video_encoder_configurations(self, request: ET.Element) -> str:
        """
        Handle GetVideoEncoderConfigurations request.
        Returns all video encoder configurations for the device's profiles.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Generate encoder configs for all profiles
            configs_xml = ""
            with self.profiles_lock:
                for profile in self.media_profiles:
                    profile_dict = profile.to_dict()
                    width = profile_dict['resolution']['width']
                    height = profile_dict['resolution']['height']
                    configs_xml += f"""
    <trt:Configurations token="VideoEncoder_{profile.token}">
      <tt:Name>VideoEncoder_{profile.token}</tt:Name>
      <tt:UseCount>1</tt:UseCount>
      <tt:Encoding>H264</tt:Encoding>
      <tt:Resolution>
        <tt:Width>{width}</tt:Width>
        <tt:Height>{height}</tt:Height>
      </tt:Resolution>
      <tt:Quality>5</tt:Quality>
      <tt:RateControl>
        <tt:FrameRateLimit>{profile.fps}</tt:FrameRateLimit>
        <tt:EncodingInterval>1</tt:EncodingInterval>
        <tt:BitrateLimit>4000</tt:BitrateLimit>
      </tt:RateControl>
      <tt:H264>
        <tt:GovLength>30</tt:GovLength>
        <tt:H264Profile>High</tt:H264Profile>
      </tt:H264>
    </trt:Configurations>
    """

            response = f"""
    <trt:GetVideoEncoderConfigurationsResponse>
      {configs_xml}
    </trt:GetVideoEncoderConfigurationsResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetVideoEncoderConfigurationsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetVideoEncoderConfigurations: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting video encoder configurations: {str(e)}")

    def _handle_get_video_source_configurations(self, request: ET.Element) -> str:
        """
        Handle GetVideoSourceConfigurations request.
        Returns all video source configurations for the device's profiles.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Generate video source configs for all profiles
            configs_xml = ""
            with self.profiles_lock:
                for profile in self.media_profiles:
                    profile_dict = profile.to_dict()
                    width = profile_dict['resolution']['width']
                    height = profile_dict['resolution']['height']
                    configs_xml += f"""
    <trt:Configurations token="VideoSourceConfig_{profile.token}">
      <tt:Name>VideoSourceConfig_{profile.token}</tt:Name>
      <tt:UseCount>1</tt:UseCount>
      <tt:SourceToken>VideoSource</tt:SourceToken>
      <tt:Bounds height="{height}" width="{width}" y="0" x="0"/>
    </trt:Configurations>
    """

            response = f"""
    <trt:GetVideoSourceConfigurationsResponse>
      {configs_xml}
    </trt:GetVideoSourceConfigurationsResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetVideoSourceConfigurationsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetVideoSourceConfigurations: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting video source configurations: {str(e)}")

    def _handle_get_video_sources(self, request: ET.Element) -> str:
        """
        Handle GetVideoSources request.
        Returns the available video sources for the device.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Single video source for simplicity, consistent with profiles
            response = f"""
    <trt:GetVideoSourcesResponse>
      <trt:VideoSources token="VideoSource">
        <tt:Framerate>30</tt:Framerate>
        <tt:Resolution>
          <tt:Width>1920</tt:Width>
          <tt:Height>1080</tt:Height>
        </tt:Resolution>
      </trt:VideoSources>
    </trt:GetVideoSourcesResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetVideoSourcesResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetVideoSources: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting video sources: {str(e)}")

    def _handle_get_video_source_configuration_options(self, request: ET.Element) -> str:
        """
        Handle GetVideoSourceConfigurationOptions request.
        Returns the configuration options available for video sources.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Extract ConfigurationToken if present (optional in ONVIF spec)
            get_options = request.find('.//trt:GetVideoSourceConfigurationOptions', NAMESPACES)
            config_token = None
            if get_options is not None:
                token_elem = get_options.find('.//trt:ConfigurationToken', NAMESPACES)
                if token_elem is not None:
                    config_token = token_elem.text

            # Simple response with bounds options for all profiles
            bounds_options = ""
            with self.profiles_lock:
                for profile in self.media_profiles:
                    profile_dict = profile.to_dict()
                    width = profile_dict['resolution']['width']
                    height = profile_dict['resolution']['height']
                    bounds_options += f"""
    <tt:BoundsRange>
      <tt:XRange>
        <tt:Min>0</tt:Min>
        <tt:Max>{width}</tt:Max>
      </tt:XRange>
      <tt:YRange>
        <tt:Min>0</tt:Min>
        <tt:Max>{height}</tt:Max>
      </tt:YRange>
      <tt:WidthRange>
        <tt:Min>{width}</tt:Min>
        <tt:Max>{width}</tt:Max>
      </tt:WidthRange>
      <tt:HeightRange>
        <tt:Min>{height}</tt:Min>
        <tt:Max>{height}</tt:Max>
      </tt:HeightRange>
    </tt:BoundsRange>
    """

            response = f"""
    <trt:GetVideoSourceConfigurationOptionsResponse>
      <trt:Options>
        {bounds_options}
      </trt:Options>
    </trt:GetVideoSourceConfigurationOptionsResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetVideoSourceConfigurationOptionsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetVideoSourceConfigurationOptions: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting video source configuration options: {str(e)}")

    def _handle_get_audio_source_configurations(self, request: ET.Element) -> str:
        """
        Handle GetAudioSourceConfigurations request.
        Returns audio source configurations (none supported in this implementation).

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # No audio sources supported, return empty response
            response = """
    <trt:GetAudioSourceConfigurationsResponse>
    </trt:GetAudioSourceConfigurationsResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetAudioSourceConfigurationsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetAudioSourceConfigurations: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting audio source configurations: {str(e)}")

    def _handle_get_compatible_video_encoder_configurations(self, request: ET.Element) -> str:
        """
        Handle GetCompatibleVideoEncoderConfigurations request.
        Returns video encoder configurations compatible with a specific profile.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Extract ProfileToken from the request
            get_configs = request.find('.//trt:GetCompatibleVideoEncoderConfigurations', NAMESPACES)
            if get_configs is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetCompatibleVideoEncoderConfigurations element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = get_configs.find('.//trt:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Find the matching profile
            profile = None
            with self.profiles_lock:
                for p in self.media_profiles:
                    if p.token == profile_token:
                        profile = p
                        break

            if profile is None:
                return XMLGenerator.generate_fault_response(
                    f"Profile {profile_token} not found",
                    "ter:InvalidArgVal"
                )

            # Generate compatible encoder config (same as profile's encoder)
            profile_dict = profile.to_dict()
            width = profile_dict['resolution']['width']
            height = profile_dict['resolution']['height']
            response = f"""
    <trt:GetCompatibleVideoEncoderConfigurationsResponse>
      <trt:Configurations token="VideoEncoder_{profile.token}">
        <tt:Name>VideoEncoder_{profile.token}</tt:Name>
        <tt:UseCount>1</tt:UseCount>
        <tt:Encoding>H264</tt:Encoding>
        <tt:Resolution>
          <tt:Width>{width}</tt:Width>
          <tt:Height>{height}</tt:Height>
        </tt:Resolution>
        <tt:Quality>5</tt:Quality>
        <tt:RateControl>
          <tt:FrameRateLimit>{profile.fps}</tt:FrameRateLimit>
          <tt:EncodingInterval>1</tt:EncodingInterval>
          <tt:BitrateLimit>4000</tt:BitrateLimit>
        </tt:RateControl>
        <tt:H264>
          <tt:GovLength>30</tt:GovLength>
          <tt:H264Profile>High</tt:H264Profile>
        </tt:H264>
      </trt:Configurations>
    </trt:GetCompatibleVideoEncoderConfigurationsResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetCompatibleVideoEncoderConfigurationsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetCompatibleVideoEncoderConfigurations: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(
                f"Error getting compatible video encoder configurations: {str(e)}")

    def _handle_get_video_encoder_configuration_options(self, request: ET.Element) -> str:
        """
        Handle GetVideoEncoderConfigurationOptions request.
        Returns a comprehensive set of configuration options for video encoders.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Extract ConfigurationToken if present (optional)
            get_options = request.find('.//trt:GetVideoEncoderConfigurationOptions', NAMESPACES)
            config_token = None
            if get_options is not None:
                token_elem = get_options.find('.//trt:ConfigurationToken', NAMESPACES)
                if token_elem is not None:
                    config_token = token_elem.text

            # Define a broad set of options (not tied strictly to profiles)
            response = f"""
    <trt:GetVideoEncoderConfigurationOptionsResponse>
      <trt:Options>
        <tt:JPEG>
          <tt:ResolutionsAvailable>
            <tt:Width>1920</tt:Width>
            <tt:Height>1080</tt:Height>
          </tt:ResolutionsAvailable>
          <tt:ResolutionsAvailable>
            <tt:Width>1280</tt:Width>
            <tt:Height>720</tt:Height>
          </tt:ResolutionsAvailable>
          <tt:ResolutionsAvailable>
            <tt:Width>640</tt:Width>
            <tt:Height>480</tt:Height>
          </tt:ResolutionsAvailable>
          <tt:QualityRange>
            <tt:Min>1</tt:Min>
            <tt:Max>100</tt:Max>
          </tt:QualityRange>
          <tt:FrameRateRange>
            <tt:Min>1</tt:Min>
            <tt:Max>30</tt:Max>
          </tt:FrameRateRange>
          <tt:EncodingIntervalRange>
            <tt:Min>1</tt:Min>
            <tt:Max>10</tt:Max>
          </tt:EncodingIntervalRange>
          <tt:BitrateRange>
            <tt:Min>64</tt:Min>
            <tt:Max>8000</tt:Max>
          </tt:BitrateRange>
        </tt:JPEG>
        <tt:H264>
          <tt:ResolutionsAvailable>
            <tt:Width>1920</tt:Width>
            <tt:Height>1080</tt:Height>
          </tt:ResolutionsAvailable>
          <tt:ResolutionsAvailable>
            <tt:Width>1280</tt:Width>
            <tt:Height>720</tt:Height>
          </tt:ResolutionsAvailable>
          <tt:ResolutionsAvailable>
            <tt:Width>640</tt:Width>
            <tt:Height>480</tt:Height>
          </tt:ResolutionsAvailable>
          <tt:GovLengthRange>
            <tt:Min>10</tt:Min>
            <tt:Max>60</tt:Max>
          </tt:GovLengthRange>
          <tt:FrameRateRange>
            <tt:Min>1</tt:Min>
            <tt:Max>60</tt:Max>
          </tt:FrameRateRange>
          <tt:EncodingIntervalRange>
            <tt:Min>1</tt:Min>
            <tt:Max>10</tt:Max>
          </tt:EncodingIntervalRange>
          <tt:H264ProfilesSupported>Baseline</tt:H264ProfilesSupported>
          <tt:H264ProfilesSupported>Main</tt:H264ProfilesSupported>
          <tt:H264ProfilesSupported>High</tt:H264ProfilesSupported>
          <tt:BitrateRange>
            <tt:Min>64</tt:Min>
            <tt:Max>10000</tt:Max>
          </tt:BitrateRange>
        </tt:H264>
        <tt:QualityRange>
          <tt:Min>1</tt:Min>
          <tt:Max>10</tt:Max>
        </tt:QualityRange>
      </tt:Options>
    </trt:GetVideoEncoderConfigurationOptionsResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetVideoEncoderConfigurationOptionsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetVideoEncoderConfigurationOptions: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting video encoder configuration options: {str(e)}")



    def _handle_get_hostname(self, request: ET.Element) -> str:
        """
        Handle GetHostname request.
        Returns the hostname of the ONVIF device.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        try:
            # Use server_ip as a fallback hostname, or get from socket if preferred
            hostname = self.server_ip  # Simple fallback; could use socket.gethostname() if needed
            response = f"""
    <tds:GetHostnameResponse>
      <tds:HostnameInformation>
        <tt:FromDHCP>false</tt:FromDHCP>
        <tt:Name>{hostname}</tt:Name>
      </tds:HostnameInformation>
    </tds:GetHostnameResponse>
    """
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetHostnameResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling GetHostname: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting hostname: {str(e)}")

    from onvif import NAMESPACES, generate_soap_response, generate_fault_response  # Ensure these are imported
    import logging
    from xml.etree import ElementTree as ET

    logger = logging.getLogger(__name__)

    def handle_media_service(self, soap_request: str) -> str:
        """
        Handle ONVIF Media service requests with enhanced protocol support and diagnostics.

        Args:
            soap_request: SOAP request XML as a string

        Returns:
            str: SOAP response XML
        """
        logger.debug(f"Received media service request: {soap_request[:1000]}...")

        # Specifically log GetStreamUri requests
        if "GetStreamUri" in soap_request:
            logger.info(f"GetStreamUri request received: {soap_request[:500]}...")

        try:
            # Parse XML safely
            try:
                root = ET.fromstring(soap_request)
            except ET.ParseError as e:
                logger.error(f"Failed to parse SOAP request: {e}")
                return generate_fault_response("Invalid SOAP request", "ter:InvalidArgVal")

            # Extract SOAP Body using NAMESPACES
            body = root.find('.//soap:Body', NAMESPACES)
            if body is None:
                logger.error("No SOAP Body found in request")
                return generate_fault_response("Missing SOAP Body", "ter:InvalidArgVal")

            # Find the action element
            action_element = None
            for child in body:
                if child.tag.startswith("{"):
                    action_element = child
                    break

            if action_element is None:
                logger.error("No action element found in SOAP Body")
                return generate_fault_response("No action element found", "ter:InvalidArgVal")

            # Extract the local action name
            local_name = action_element.tag.split('}')[-1]
            logger.info(f"Media service action requested: {local_name}")

            # Define handler map for media service actions
            handler_map = {
                'GetProfiles': self._handle_get_profiles,
                'GetProfile': self._handle_get_profile,
                'GetStreamUri': self._handle_get_stream_uri,
                'GetSnapshotUri': self._handle_get_snapshot_uri,
                'GetVideoEncoderConfigurations': self._handle_get_video_encoder_configurations,
                'GetVideoSourceConfigurations': self._handle_get_video_source_configurations,
                'GetVideoSources': self._handle_get_video_sources,
                'GetServiceCapabilities': lambda r: self._handle_get_service_capabilities(r, 'media'),
                'GetVideoSourceConfigurationOptions': self._handle_get_video_source_configuration_options,
                'GetAudioSourceConfigurations': self._handle_get_audio_source_configurations,
                'GetCompatibleVideoEncoderConfigurations': self._handle_get_compatible_video_encoder_configurations,
                'GetVideoEncoderConfigurationOptions': self._handle_get_video_encoder_configuration_options,
                'GetGuaranteedNumberOfVideoEncoderInstances': self._handle_get_guaranteed_number_of_video_encoder_instances,
                'StartMulticastStreaming': self._handle_start_multicast_streaming,
                'StopMulticastStreaming': self._handle_stop_multicast_streaming,
                'GetOSDs': self._handle_get_osds,
                'GetOSDOptions': self._handle_get_osd_options,
                'SetOSD': self._handle_set_osd,
                'SetSynchronizationPoint': self._handle_set_synchronization_point,
            }

            # Execute the handler if found
            handler = handler_map.get(local_name)
            if handler:
                response = handler(action_element)
                if local_name == "GetStreamUri":
                    logger.info(f"GetStreamUri response: {response[:500]}...")
                return response
            else:
                logger.warning(f"Unsupported media service action: {local_name}")
                return generate_fault_response(
                    f"Unsupported action: {local_name}",
                    "ter:ActionNotSupported"
                )

        except Exception as e:
            logger.error(f"Error handling media service request: {e}", exc_info=True)
            return generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError")


    def handle_events_service(self, soap_request: str) -> str:
        """
        Handle ONVIF Events service requests.
        Implements Pull-Point Subscription and basic event delivery.

        Args:
            soap_request: SOAP request XML

        Returns:
            str: SOAP response XML
        """
        try:
            root = parse_xml_safely(soap_request)
            if root is None:
                return XMLGenerator.generate_fault_response("Invalid SOAP request")

            body = root.find('.//soap:Body', NAMESPACES)
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

            # Log events service actions for debugging
            logger.info(f"Events service action requested: {local_name}")

            # Events service handlers
            handler_map = {
                'GetEventProperties': self._handle_get_event_properties,
                'CreatePullPointSubscription': self._handle_create_pull_point_subscription,
                'PullMessages': self._handle_pull_messages,
                'Unsubscribe': self._handle_unsubscribe,
                'Renew': self._handle_renew,
                'SetSynchronizationPoint': self._handle_set_synchronization_point,
                'GetServiceCapabilities': lambda r: self._handle_get_service_capabilities(r, 'events'),
            }

            handler = handler_map.get(local_name)
            if handler:
                return handler(root)
            else:
                logger.warning(f"Unsupported events service action: {local_name}")
                return XMLGenerator.generate_fault_response(
                    f"Unsupported action: {local_name}",
                    "ter:ActionNotSupported"
                )
        except Exception as e:
            logger.error(f"Error handling events service request: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Internal error: {str(e)}")

    def handle_imaging_service(self, soap_request: str) -> str:
        """
        Handle ONVIF Imaging service requests.
        Implements basic imaging settings.

        Args:
            soap_request: SOAP request XML

        Returns:
            str: SOAP response XML
        """
        try:
            root = parse_xml_safely(soap_request)
            if root is None:
                return XMLGenerator.generate_fault_response("Invalid SOAP request")

            body = root.find('.//soap:Body', NAMESPACES)
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

            # Log imaging service actions for debugging
            logger.info(f"Imaging service action requested: {local_name}")

            # Imaging service handlers
            handler_map = {
                'GetImagingSettings': self._handle_get_imaging_settings,
                'SetImagingSettings': self._handle_set_imaging_settings,
                'GetOptions': self._handle_get_imaging_options,
                'GetMoveOptions': self._handle_get_move_options,
                'Move': self._handle_imaging_move,
                'Stop': self._handle_imaging_stop,
                'GetStatus': self._handle_get_imaging_status,
                'GetServiceCapabilities': lambda r: self._handle_get_service_capabilities(r, 'imaging'),
            }

            handler = handler_map.get(local_name)
            if handler:
                return handler(root)
            else:
                logger.warning(f"Unsupported imaging service action: {local_name}")
                return XMLGenerator.generate_fault_response(
                    f"Unsupported action: {local_name}",
                    "ter:ActionNotSupported"
                )
        except Exception as e:
            logger.error(f"Error handling imaging service request: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Internal error: {str(e)}")

    def handle_ptz_service(self, soap_request: str) -> str:
        """
        Handle ONVIF PTZ service requests.
        Implements minimal PTZ support for Profile S compliance.

        Args:
            soap_request: SOAP request XML

        Returns:
            str: SOAP response XML
        """
        try:
            root = parse_xml_safely(soap_request)
            if root is None:
                return XMLGenerator.generate_fault_response("Invalid SOAP request")

            body = root.find('.//soap:Body', NAMESPACES)
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

            # Log PTZ service actions for debugging
            logger.info(f"PTZ service action requested: {local_name}")

            # PTZ service handlers
            handler_map = {
                'GetConfigurations': self._handle_get_ptz_configurations,
                'GetConfiguration': self._handle_get_ptz_configuration,
                'GetConfigurationOptions': self._handle_get_ptz_configuration_options,
                'GetStatus': self._handle_get_ptz_status,
                'GetPresets': self._handle_get_presets,
                'GotoPreset': self._handle_goto_preset,
                'ContinuousMove': self._handle_continuous_move,
                'RelativeMove': self._handle_relative_move,
                'AbsoluteMove': self._handle_absolute_move,
                'Stop': self._handle_ptz_stop,
                'GetServiceCapabilities': lambda r: self._handle_get_service_capabilities(r, 'ptz'),
            }

            handler = handler_map.get(local_name)
            if handler:
                return handler(root)
            else:
                logger.warning(f"Unsupported PTZ service action: {local_name}")
                return XMLGenerator.generate_fault_response(
                    f"Unsupported action: {local_name}",
                    "ter:ActionNotSupported"
                )
        except Exception as e:
            logger.error(f"Error handling PTZ service request: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Internal error: {str(e)}")

    #
    # Event service handlers
    #
    def _handle_get_event_properties(self, request: ET.Element) -> str:
        """
        Handle GetEventProperties request.
        Enhanced with more comprehensive event topics for Profile S compliance.
        """
        response = """
    <tev:GetEventPropertiesResponse>
      <tev:TopicNamespaceLocation>http://www.onvif.org/ver10/topics/topicns.xml</tev:TopicNamespaceLocation>
      <wsnt:FixedTopicSet>true</wsnt:FixedTopicSet>
      <wstop:TopicSet>
        <!-- Device management events -->
        <tns1:Device xmlns:tns1="http://www.onvif.org/ver10/topics">
          <tns1:Trigger>
            <tns1:DigitalInput wstop:topic="true">
              <tns1:State wstop:topic="true"/>
            </tns1:DigitalInput>
            <tns1:Status wstop:topic="true"/>
          </tns1:Trigger>
          <tns1:IO>
            <tns1:RelayOutput wstop:topic="true">
              <tns1:LogicalState wstop:topic="true"/>
            </tns1:RelayOutput>
          </tns1:IO>
          <tns1:Management>
            <tns1:ConnectionLost wstop:topic="true"/>
            <tns1:ConnectionRestored wstop:topic="true"/>
          </tns1:Management>
        </tns1:Device>

        <!-- Video source events -->
        <tns1:VideoSource xmlns:tns1="http://www.onvif.org/ver10/topics">
          <tns1:VideoStream wstop:topic="true">
            <tns1:Status wstop:topic="true"/>
          </tns1:VideoStream>
          <tns1:VideoMotion wstop:topic="true"/>
          <tns1:TamperDetection wstop:topic="true"/>
          <tns1:ImageTooBlurry wstop:topic="true"/>
          <tns1:ImageTooDark wstop:topic="true"/>
          <tns1:ImageTooBright wstop:topic="true"/>
        </tns1:VideoSource>

        <!-- Analytics events -->
        <tns1:VideoAnalytics xmlns:tns1="http://www.onvif.org/ver10/topics">
          <tns1:Motion wstop:topic="true">
            <tns1:Motion wstop:topic="true"/>
          </tns1:Motion>
          <tns1:ObjectDetection wstop:topic="true">
            <tns1:Object wstop:topic="true"/>
          </tns1:ObjectDetection>
        </tns1:VideoAnalytics>

        <!-- Recording and media events -->
        <tns1:Recording xmlns:tns1="http://www.onvif.org/ver10/topics">
          <tns1:RecordingStarted wstop:topic="true"/>
          <tns1:RecordingStopped wstop:topic="true"/>
        </tns1:Recording>

        <!-- Configuration events -->
        <tns1:Configuration xmlns:tns1="http://www.onvif.org/ver10/topics">
          <tns1:ProfileChanged wstop:topic="true"/>
          <tns1:VideoSourceConfigurationChanged wstop:topic="true"/>
          <tns1:VideoEncoderConfigurationChanged wstop:topic="true"/>
        </tns1:Configuration>
      </wstop:TopicSet>
      <wsnt:TopicExpressionDialect>http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet</wsnt:TopicExpressionDialect>
      <wsnt:TopicExpressionDialect>http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete</wsnt:TopicExpressionDialect>
      <wsnt:MessageContentFilterDialect>http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter</wsnt:MessageContentFilterDialect>
      <tt:MessageContentSchemaLocation>http://www.onvif.org/ver10/schema/onvif.xsd</tt:MessageContentSchemaLocation>
    </tev:GetEventPropertiesResponse>
    """
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/events/wsdl/GetEventPropertiesResponse",
            response
        )

    def _handle_create_pull_point_subscription(self, request: ET.Element) -> str:
        """
        Handle CreatePullPointSubscription request.
        Creates a pull-point subscription for events.
        """
        try:
            # Extract subscription parameters
            create_subscription = request.find('.//tev:CreatePullPointSubscription', NAMESPACES)

            # Default values
            initial_termination_time = 60  # 1 minute by default

            # Extract InitialTerminationTime if specified
            initial_term_elem = create_subscription.find('.//wsnt:InitialTerminationTime', NAMESPACES)
            if initial_term_elem is not None:
                try:
                    # PT60S format = 60 seconds
                    if initial_term_elem.text.startswith('PT'):
                        seconds_str = initial_term_elem.text[2:-1]
                        if seconds_str.endswith('S'):
                            initial_termination_time = int(seconds_str[:-1])
                        elif seconds_str.endswith('M'):
                            initial_termination_time = int(seconds_str[:-1]) * 60
                        elif seconds_str.endswith('H'):
                            initial_termination_time = int(seconds_str[:-1]) * 3600
                except Exception as e:
                    logger.warning(f"Error parsing InitialTerminationTime: {e}")

            # Create a subscription
            subscription_id, expiration_time = self.event_emitter.create_subscription(
                address="pull-point",
                expires=initial_termination_time
            )

            # Format expiration time for response
            expiration_str = expiration_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # Generate response
            response = f"""
<tev:CreatePullPointSubscriptionResponse>
  <tev:SubscriptionReference>
    <wsa:Address>http://{self.server_ip}:{self.onvif_port}/onvif/events_service</wsa:Address>
    <wsa:ReferenceParameters>
      <tev:SubscriptionId>{subscription_id}</tev:SubscriptionId>
    </wsa:ReferenceParameters>
  </tev:SubscriptionReference>
  <wsnt:CurrentTime>{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')}</wsnt:CurrentTime>
  <wsnt:TerminationTime>{expiration_str}</wsnt:TerminationTime>
</tev:CreatePullPointSubscriptionResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/events/wsdl/CreatePullPointSubscriptionResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error creating pull-point subscription: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error creating subscription: {str(e)}")

    def _handle_pull_messages(self, request: ET.Element) -> str:
        """
        Handle PullMessages request.
        Gets events for a pull-point subscription.
        """
        try:
            # Extract parameters
            pull_messages = request.find('.//tev:PullMessages', NAMESPACES)

            subscription_id = None
            timeout = 60  # Default timeout in seconds
            message_limit = 10  # Default message limit

            # Extract subscription ID
            subscription_ref = request.find('.//wsa:ReferenceParameters', NAMESPACES)
            if subscription_ref is not None:
                subscription_id_elem = subscription_ref.find('.//tev:SubscriptionId', NAMESPACES)
                if subscription_id_elem is not None:
                    subscription_id = subscription_id_elem.text

            # If no subscription ID in headers, try to get it from the body
            if subscription_id is None:
                subscription_id_elem = pull_messages.find('.//tev:SubscriptionId', NAMESPACES)
                if subscription_id_elem is not None:
                    subscription_id = subscription_id_elem.text

            # Extract timeout
            timeout_elem = pull_messages.find('.//tev:Timeout', NAMESPACES)
            if timeout_elem is not None:
                try:
                    # PT60S format = 60 seconds
                    if timeout_elem.text.startswith('PT'):
                        seconds_str = timeout_elem.text[2:-1]
                        if seconds_str.endswith('S'):
                            timeout = int(seconds_str[:-1])
                        elif seconds_str.endswith('M'):
                            timeout = int(seconds_str[:-1]) * 60
                        elif seconds_str.endswith('H'):
                            timeout = int(seconds_str[:-1]) * 3600
                except Exception as e:
                    logger.warning(f"Error parsing Timeout: {e}")

            # Extract message limit
            limit_elem = pull_messages.find('.//tev:MessageLimit', NAMESPACES)
            if limit_elem is not None:
                try:
                    message_limit = int(limit_elem.text)
                except Exception as e:
                    logger.warning(f"Error parsing MessageLimit: {e}")

            # Validate subscription ID
            if subscription_id is None:
                return XMLGenerator.generate_fault_response(
                    "Missing subscription ID",
                    "ter:InvalidArgVal"
                )

            # Pull events
            events, current_seq = self.event_emitter.pull_events(
                subscription_id=subscription_id,
                timeout=timeout
            )

            # Limit the number of events
            events = events[:message_limit]

            # Generate response
            notification_messages = ""
            for event in events:
                topic = event['topic']
                timestamp = event['timestamp']
                source = event['source']
                sequence = event['sequence']

                # Format event data as SimpleItem elements
                data_items = ""
                for key, value in event['data'].items():
                    if isinstance(value, bool):
                        data_items += f'<tt:SimpleItem Name="{key}" Value="{str(value).lower()}"/>'
                    else:
                        data_items += f'<tt:SimpleItem Name="{key}" Value="{value}"/>'

                notification_messages += f"""
<wsnt:NotificationMessage>
  <wsnt:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">{topic}</wsnt:Topic>
  <wsnt:ProducerReference>
    <wsa:Address>http://{self.server_ip}:{self.onvif_port}/onvif/events_service</wsa:Address>
  </wsnt:ProducerReference>
  <wsnt:Message>
    <tt:Message UtcTime="{timestamp}" PropertyOperation="Changed">
      <tt:Source>
        <tt:SimpleItem Name="Source" Value="{source}"/>
      </tt:Source>
      <tt:Key>
        <tt:SimpleItem Name="Id" Value="{sequence}"/>
      </tt:Key>
      <tt:Data>
        {data_items}
      </tt:Data>
    </tt:Message>
  </wsnt:Message>
</wsnt:NotificationMessage>
"""

            current_time = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            response = f"""
<tev:PullMessagesResponse>
  <tev:CurrentTime>{current_time}</tev:CurrentTime>
  <tev:TerminationTime>{current_time}</tev:TerminationTime>
  {notification_messages}
</tev:PullMessagesResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/events/wsdl/PullMessagesResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error pulling messages: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error pulling messages: {str(e)}")

    def _handle_unsubscribe(self, request: ET.Element) -> str:
        """
        Handle Unsubscribe request.
        Removes a pull-point subscription.
        """
        try:
            # Extract subscription ID
            subscription_id = None

            subscription_ref = request.find('.//wsa:ReferenceParameters', NAMESPACES)
            if subscription_ref is not None:
                subscription_id_elem = subscription_ref.find('.//tev:SubscriptionId', NAMESPACES)
                if subscription_id_elem is not None:
                    subscription_id = subscription_id_elem.text

            # Validate subscription ID
            if subscription_id is None:
                return XMLGenerator.generate_fault_response(
                    "Missing subscription ID",
                    "ter:InvalidArgVal"
                )

            # Unsubscribe
            success = self.event_emitter.unsubscribe(subscription_id)

            if not success:
                return XMLGenerator.generate_fault_response(
                    "Invalid subscription ID",
                    "ter:InvalidArgVal"
                )

            # Generate response
            response = """
<wsnt:UnsubscribeResponse>
</wsnt:UnsubscribeResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://docs.oasis-open.org/wsn/b-2/UnsubscribeResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error unsubscribing: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error unsubscribing: {str(e)}")

    def _handle_renew(self, request: ET.Element) -> str:
        """
        Handle Renew request.
        Extends the expiration time of a pull-point subscription.
        """
        try:
            # Extract parameters
            renew = request.find('.//wsnt:Renew', NAMESPACES)

            subscription_id = None
            termination_time = 60  # Default renewal time in seconds

            # Extract subscription ID
            subscription_ref = request.find('.//wsa:ReferenceParameters', NAMESPACES)
            if subscription_ref is not None:
                subscription_id_elem = subscription_ref.find('.//tev:SubscriptionId', NAMESPACES)
                if subscription_id_elem is not None:
                    subscription_id = subscription_id_elem.text

            # Extract termination time
            term_time_elem = renew.find('.//wsnt:TerminationTime', NAMESPACES)
            if term_time_elem is not None:
                try:
                    # PT60S format = 60 seconds
                    if term_time_elem.text.startswith('PT'):
                        seconds_str = term_time_elem.text[2:-1]
                        if seconds_str.endswith('S'):
                            termination_time = int(seconds_str[:-1])
                        elif seconds_str.endswith('M'):
                            termination_time = int(seconds_str[:-1]) * 60
                        elif seconds_str.endswith('H'):
                            termination_time = int(seconds_str[:-1]) * 3600
                except Exception as e:
                    logger.warning(f"Error parsing TerminationTime: {e}")

            # Validate subscription ID
            if subscription_id is None:
                return XMLGenerator.generate_fault_response(
                    "Missing subscription ID",
                    "ter:InvalidArgVal"
                )

            # Renew subscription
            new_expiration = self.event_emitter.renew_subscription(
                subscription_id=subscription_id,
                extends=termination_time
            )

            if new_expiration is None:
                return XMLGenerator.generate_fault_response(
                    "Invalid subscription ID",
                    "ter:InvalidArgVal"
                )

            # Format expiration time for response
            expiration_str = new_expiration.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # Generate response
            response = f"""
<wsnt:RenewResponse>
  <wsnt:TerminationTime>{expiration_str}</wsnt:TerminationTime>
  <wsnt:CurrentTime>{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')}</wsnt:CurrentTime>
</wsnt:RenewResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://docs.oasis-open.org/wsn/b-2/RenewResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error renewing subscription: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error renewing subscription: {str(e)}")

    def _handle_set_synchronization_point(self, request: ET.Element) -> str:
        """
        Handle SetSynchronizationPoint request.
        Adds a system state event to the subscription.
        """
        try:
            # Extract subscription ID
            subscription_id = None

            subscription_ref = request.find('.//wsa:ReferenceParameters', NAMESPACES)
            if subscription_ref is not None:
                subscription_id_elem = subscription_ref.find('.//tev:SubscriptionId', NAMESPACES)
                if subscription_id_elem is not None:
                    subscription_id = subscription_id_elem.text

            # Validate subscription ID
            if subscription_id is None:
                return XMLGenerator.generate_fault_response(
                    "Missing subscription ID",
                    "ter:InvalidArgVal"
                )

            # Validate subscription exists
            subscription_info = self.event_emitter.get_subscription_info(subscription_id)
            if subscription_info is None:
                return XMLGenerator.generate_fault_response(
                    "Invalid subscription ID",
                    "ter:InvalidArgVal"
                )

            # Add a system state event
            self.event_emitter.add_event(
                topic="tns1:Device/tns1:Trigger/tns1:Status",
                source="SynchronizationPoint",
                data={
                    "State": True,
                    "Token": "SyncPoint"
                }
            )

            # Generate response
            response = """
<tev:SetSynchronizationPointResponse>
</tev:SetSynchronizationPointResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/events/wsdl/SetSynchronizationPointResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error setting synchronization point: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error setting synchronization point: {str(e)}")

    #
    # Imaging service handlers
    #
    def _handle_get_imaging_settings(self, request: ET.Element) -> str:
        """
        Handle GetImagingSettings request.
        Returns the current imaging settings.
        """
        try:
            # Extract video source token
            get_imaging_settings = request.find('.//timg:GetImagingSettings', NAMESPACES)

            if get_imaging_settings is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetImagingSettings element",
                    "ter:InvalidArgVal"
                )

            video_source_token_elem = get_imaging_settings.find('.//timg:VideoSourceToken', NAMESPACES)
            if video_source_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing VideoSourceToken",
                    "ter:InvalidArgVal"
                )

            video_source_token = video_source_token_elem.text

            # Get imaging settings (in a real implementation, this would depend on the video source)
            settings = self.imaging_settings

            # Generate response
            response = f"""
<timg:GetImagingSettingsResponse>
  <timg:ImagingSettings>
    <tt:Brightness>{settings['brightness']}</tt:Brightness>
    <tt:Contrast>{settings['contrast']}</tt:Contrast>
    <tt:ColorSaturation>{settings['saturation']}</tt:ColorSaturation>
    <tt:Sharpness>{settings['sharpness']}</tt:Sharpness>
    <tt:Exposure>
      <tt:Mode>{settings['exposure']['mode']}</tt:Mode>
      <tt:Priority>{settings['exposure']['priority']}</tt:Priority>
      <tt:MinExposureTime>{settings['exposure']['minExposureTime']}</tt:MinExposureTime>
      <tt:MaxExposureTime>{settings['exposure']['maxExposureTime']}</tt:MaxExposureTime>
    </tt:Exposure>
    <tt:Focus>
      <tt:AutoFocusMode>{settings['focus']['mode']}</tt:AutoFocusMode>
      <tt:DefaultSpeed>{settings['focus']['defaultSpeed']}</tt:DefaultSpeed>
      <tt:NearLimit>{settings['focus']['nearLimit']}</tt:NearLimit>
      <tt:FarLimit>{settings['focus']['farLimit']}</tt:FarLimit>
    </tt:Focus>
    <tt:WhiteBalance>
      <tt:Mode>{settings['whiteBalance']['mode']}</tt:Mode>
      <tt:CbGain>{settings['whiteBalance']['cbGain']}</tt:CbGain>
      <tt:CrGain>{settings['whiteBalance']['crGain']}</tt:CrGain>
    </tt:WhiteBalance>
  </timg:ImagingSettings>
</timg:GetImagingSettingsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/imaging/wsdl/GetImagingSettingsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting imaging settings: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting imaging settings: {str(e)}")

    def _handle_set_imaging_settings(self, request: ET.Element) -> str:
        """
        Handle SetImagingSettings request.
        Sets imaging settings for a video source.
        """
        try:
            # Extract parameters
            set_imaging_settings = request.find('.//timg:SetImagingSettings', NAMESPACES)

            if set_imaging_settings is None:
                return XMLGenerator.generate_fault_response(
                    "Missing SetImagingSettings element",
                    "ter:InvalidArgVal"
                )

            video_source_token_elem = set_imaging_settings.find('.//timg:VideoSourceToken', NAMESPACES)
            if video_source_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing VideoSourceToken",
                    "ter:InvalidArgVal"
                )

            video_source_token = video_source_token_elem.text

            # Extract imaging settings
            imaging_settings_elem = set_imaging_settings.find('.//timg:ImagingSettings', NAMESPACES)
            if imaging_settings_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ImagingSettings",
                    "ter:InvalidArgVal"
                )

            # Update imaging settings (we don't actually modify anything in this implementation)
            # In a real implementation, you would update the camera's imaging settings

            # Generate an event for the settings change
            self.event_emitter.add_event(
                topic="tns1:VideoSource/tns1:ImagingSettings/tns1:ImagingSettingsApplied",
                source=f"VideoSource_{video_source_token}",
                data={
                    "Token": video_source_token
                }
            )

            # Generate response
            response = """
<timg:SetImagingSettingsResponse>
</timg:SetImagingSettingsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/imaging/wsdl/SetImagingSettingsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error setting imaging settings: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error setting imaging settings: {str(e)}")

    def _handle_get_imaging_options(self, request: ET.Element) -> str:
        """
        Handle GetOptions request.
        Returns imaging setting options for a video source.
        """
        try:
            # Extract video source token
            get_options = request.find('.//timg:GetOptions', NAMESPACES)

            if get_options is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetOptions element",
                    "ter:InvalidArgVal"
                )

            video_source_token_elem = get_options.find('.//timg:VideoSourceToken', NAMESPACES)
            if video_source_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing VideoSourceToken",
                    "ter:InvalidArgVal"
                )

            video_source_token = video_source_token_elem.text

            # Generate response with options
            response = """
<timg:GetOptionsResponse>
  <timg:ImagingOptions>
    <tt:Brightness>
      <tt:Min>0</tt:Min>
      <tt:Max>100</tt:Max>
    </tt:Brightness>
    <tt:Contrast>
      <tt:Min>0</tt:Min>
      <tt:Max>100</tt:Max>
    </tt:Contrast>
    <tt:ColorSaturation>
      <tt:Min>0</tt:Min>
      <tt:Max>100</tt:Max>
    </tt:ColorSaturation>
    <tt:Sharpness>
      <tt:Min>0</tt:Min>
      <tt:Max>100</tt:Max>
    </tt:Sharpness>
    <tt:Exposure>
      <tt:Mode>
        <tt:Mode>AUTO</tt:Mode>
        <tt:Mode>MANUAL</tt:Mode>
      </tt:Mode>
      <tt:Priority>
        <tt:Priority>LowNoise</tt:Priority>
        <tt:Priority>FrameRate</tt:Priority>
      </tt:Priority>
      <tt:MinExposureTime>
        <tt:Min>1</tt:Min>
        <tt:Max>10000</tt:Max>
      </tt:MinExposureTime>
      <tt:MaxExposureTime>
        <tt:Min>1000</tt:Min>
        <tt:Max>100000</tt:Max>
      </tt:MaxExposureTime>
    </tt:Exposure>
    <tt:Focus>
      <tt:AutoFocusModes>
        <tt:AutoFocusMode>AUTO</tt:AutoFocusMode>
        <tt:AutoFocusMode>MANUAL</tt:AutoFocusMode>
      </tt:AutoFocusModes>
      <tt:DefaultSpeed>
        <tt:Min>0.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:DefaultSpeed>
      <tt:NearLimit>
        <tt:Min>0.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:NearLimit>
      <tt:FarLimit>
        <tt:Min>0.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:FarLimit>
    </tt:Focus>
    <tt:WhiteBalance>
      <tt:Mode>
        <tt:Mode>AUTO</tt:Mode>
        <tt:Mode>MANUAL</tt:Mode>
      </tt:Mode>
      <tt:YrGain>
        <tt:Min>0.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:YrGain>
      <tt:YbGain>
        <tt:Min>0.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:YbGain>
    </tt:WhiteBalance>
  </timg:ImagingOptions>
</timg:GetOptionsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/imaging/wsdl/GetOptionsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting imaging options: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting imaging options: {str(e)}")

    def _handle_get_move_options(self, request: ET.Element) -> str:
        """
        Handle GetMoveOptions request.
        Returns options for the focus move operation.
        """
        try:
            # Extract video source token
            get_move_options = request.find('.//timg:GetMoveOptions', NAMESPACES)

            if get_move_options is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetMoveOptions element",
                    "ter:InvalidArgVal"
                )

            video_source_token_elem = get_move_options.find('.//timg:VideoSourceToken', NAMESPACES)
            if video_source_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing VideoSourceToken",
                    "ter:InvalidArgVal"
                )

            video_source_token = video_source_token_elem.text

            # Generate response with options
            response = """
<timg:GetMoveOptionsResponse>
  <timg:MoveOptions>
    <tt:Absolute>
      <tt:Position>
        <tt:Min>0.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:Position>
      <tt:Speed>
        <tt:Min>0.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:Speed>
    </tt:Absolute>
    <tt:Relative>
      <tt:Distance>
        <tt:Min>-1.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:Distance>
      <tt:Speed>
        <tt:Min>0.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:Speed>
    </tt:Relative>
    <tt:Continuous>
      <tt:Speed>
        <tt:Min>-1.0</tt:Min>
        <tt:Max>1.0</tt:Max>
      </tt:Speed>
    </tt:Continuous>
  </timg:MoveOptions>
</timg:GetMoveOptionsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/imaging/wsdl/GetMoveOptionsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting move options: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting move options: {str(e)}")

    def _handle_imaging_move(self, request: ET.Element) -> str:
        """
        Handle Move request.
        Initiates a focus movement (not actually implemented).
        """
        try:
            # Extract parameters
            move = request.find('.//timg:Move', NAMESPACES)

            if move is None:
                return XMLGenerator.generate_fault_response(
                    "Missing Move element",
                    "ter:InvalidArgVal"
                )

            video_source_token_elem = move.find('.//timg:VideoSourceToken', NAMESPACES)
            if video_source_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing VideoSourceToken",
                    "ter:InvalidArgVal"
                )

            video_source_token = video_source_token_elem.text

            # In a real implementation, you would initiate a focus movement here

            # Generate response
            response = """
<timg:MoveResponse>
</timg:MoveResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/imaging/wsdl/MoveResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error initiating imaging move: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error initiating imaging move: {str(e)}")

    def _handle_imaging_stop(self, request: ET.Element) -> str:
        """
        Handle Stop request.
        Stops a focus movement (not actually implemented).
        """
        try:
            # Extract parameters
            stop = request.find('.//timg:Stop', NAMESPACES)

            if stop is None:
                return XMLGenerator.generate_fault_response(
                    "Missing Stop element",
                    "ter:InvalidArgVal"
                )

            video_source_token_elem = stop.find('.//timg:VideoSourceToken', NAMESPACES)
            if video_source_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing VideoSourceToken",
                    "ter:InvalidArgVal"
                )

            video_source_token = video_source_token_elem.text

            # In a real implementation, you would stop a focus movement here

            # Generate response
            response = """
<timg:StopResponse>
</timg:StopResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/imaging/wsdl/StopResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error stopping imaging move: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error stopping imaging move: {str(e)}")

    def _handle_get_imaging_status(self, request: ET.Element) -> str:
        """
        Handle GetStatus request.
        Returns the status of the focus.
        """
        try:
            # Extract video source token
            get_status = request.find('.//timg:GetStatus', NAMESPACES)

            if get_status is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetStatus element",
                    "ter:InvalidArgVal"
                )

            video_source_token_elem = get_status.find('.//timg:VideoSourceToken', NAMESPACES)
            if video_source_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing VideoSourceToken",
                    "ter:InvalidArgVal"
                )

            video_source_token = video_source_token_elem.text

            # Generate response with status
            response = """
<timg:GetStatusResponse>
  <timg:Status>
    <tt:Position>0.5</tt:Position>
    <tt:MoveStatus>IDLE</tt:MoveStatus>
    <tt:Error>No Error</tt:Error>
  </timg:Status>
</timg:GetStatusResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/imaging/wsdl/GetStatusResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting imaging status: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting imaging status: {str(e)}")

    #
    # PTZ service handlers
    #
    def _handle_get_ptz_configurations(self, request: ET.Element) -> str:
        """
        Handle GetConfigurations request.
        Returns all available PTZ configurations.
        """
        try:
            # Generate PTZ configurations for all profiles
            configurations = ""

            for profile_info in self.media_profiles:
                profile = profile_info.to_dict()

                configurations += f"""
<tptz:PTZConfiguration token="PTZConfig_{profile['token']}" MoveRamp="1" PresetRamp="1" PresetTourRamp="1">
  <tt:Name>PTZConfig_{profile['token']}</tt:Name>
  <tt:UseCount>1</tt:UseCount>
  <tt:NodeToken>PTZNode</tt:NodeToken>
  <tt:DefaultAbsolutePantTiltPositionSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:DefaultAbsolutePantTiltPositionSpace>
  <tt:DefaultAbsoluteZoomPositionSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:DefaultAbsoluteZoomPositionSpace>
  <tt:DefaultRelativePanTiltTranslationSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</tt:DefaultRelativePanTiltTranslationSpace>
  <tt:DefaultRelativeZoomTranslationSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace</tt:DefaultRelativeZoomTranslationSpace>
  <tt:DefaultContinuousPanTiltVelocitySpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:DefaultContinuousPanTiltVelocitySpace>
  <tt:DefaultContinuousZoomVelocitySpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:DefaultContinuousZoomVelocitySpace>
  <tt:DefaultPTZSpeed>
    <tt:PanTilt x="1.0" y="1.0" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace"/>
    <tt:Zoom x="1.0" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace"/>
  </tt:DefaultPTZSpeed>
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
</tptz:PTZConfiguration>
"""

            # Generate response
            response = f"""
<tptz:GetConfigurationsResponse>
{configurations}
</tptz:GetConfigurationsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/GetConfigurationsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting PTZ configurations: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting PTZ configurations: {str(e)}")

    def _handle_get_ptz_configuration(self, request: ET.Element) -> str:
        """
        Handle GetConfiguration request.
        Returns a specific PTZ configuration.
        """
        try:
            # Extract PTZ configuration token
            get_configuration = request.find('.//tptz:GetConfiguration', NAMESPACES)

            if get_configuration is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetConfiguration element",
                    "ter:InvalidArgVal"
                )

            ptz_configuration_token_elem = get_configuration.find('.//tptz:PTZConfigurationToken', NAMESPACES)
            if ptz_configuration_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing PTZConfigurationToken",
                    "ter:InvalidArgVal"
                )

            ptz_configuration_token = ptz_configuration_token_elem.text

            # Extract profile token from PTZ configuration token
            profile_token = ptz_configuration_token.replace("PTZConfig_", "")

            # Find the profile
            profile = None
            for profile_info in self.media_profiles:
                if profile_info.token == profile_token:
                    profile = profile_info.to_dict()
                    break

            if profile is None:
                return XMLGenerator.generate_fault_response(
                    f"Invalid PTZ configuration token: {ptz_configuration_token}",
                    "ter:InvalidArgVal"
                )

            # Generate response with PTZ configuration
            response = f"""
<tptz:GetConfigurationResponse>
  <tptz:PTZConfiguration token="{ptz_configuration_token}" MoveRamp="1" PresetRamp="1" PresetTourRamp="1">
    <tt:Name>PTZConfig_{profile_token}</tt:Name>
    <tt:UseCount>1</tt:UseCount>
    <tt:NodeToken>PTZNode</tt:NodeToken>
    <tt:DefaultAbsolutePantTiltPositionSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:DefaultAbsolutePantTiltPositionSpace>
    <tt:DefaultAbsoluteZoomPositionSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:DefaultAbsoluteZoomPositionSpace>
    <tt:DefaultRelativePanTiltTranslationSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</tt:DefaultRelativePanTiltTranslationSpace>
    <tt:DefaultRelativeZoomTranslationSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace</tt:DefaultRelativeZoomTranslationSpace>
    <tt:DefaultContinuousPanTiltVelocitySpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:DefaultContinuousPanTiltVelocitySpace>
    <tt:DefaultContinuousZoomVelocitySpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:DefaultContinuousZoomVelocitySpace>
    <tt:DefaultPTZSpeed>
      <tt:PanTilt x="1.0" y="1.0" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace"/>
      <tt:Zoom x="1.0" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace"/>
    </tt:DefaultPTZSpeed>
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
  </tptz:PTZConfiguration>
</tptz:GetConfigurationResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/GetConfigurationResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting PTZ configuration: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting PTZ configuration: {str(e)}")

    def _handle_get_ptz_configuration_options(self, request: ET.Element) -> str:
        """
        Handle GetConfigurationOptions request.
        Returns options for a PTZ configuration.
        """
        try:
            # Extract parameters
            get_configuration_options = request.find('.//tptz:GetConfigurationOptions', NAMESPACES)

            if get_configuration_options is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetConfigurationOptions element",
                    "ter:InvalidArgVal"
                )

            # The configuration token is optional
            ptz_configuration_token = None
            ptz_configuration_token_elem = get_configuration_options.find('.//tptz:ConfigurationToken', NAMESPACES)
            if ptz_configuration_token_elem is not None:
                ptz_configuration_token = ptz_configuration_token_elem.text

            # Generate response with options
            response = """
<tptz:GetConfigurationOptionsResponse>
  <tptz:PTZConfigurationOptions>
    <tt:Spaces>
      <tt:AbsolutePanTiltPositionSpace>
        <tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:URI>
        <tt:XRange>
          <tt:Min>-1.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:XRange>
        <tt:YRange>
          <tt:Min>-1.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:YRange>
      </tt:AbsolutePanTiltPositionSpace>
      <tt:AbsoluteZoomPositionSpace>
        <tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:URI>
        <tt:XRange>
          <tt:Min>0.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:XRange>
      </tt:AbsoluteZoomPositionSpace>
      <tt:RelativePanTiltTranslationSpace>
        <tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</tt:URI>
        <tt:XRange>
          <tt:Min>-1.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:XRange>
        <tt:YRange>
          <tt:Min>-1.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:YRange>
      </tt:RelativePanTiltTranslationSpace>
      <tt:RelativeZoomTranslationSpace>
        <tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace</tt:URI>
        <tt:XRange>
          <tt:Min>-1.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:XRange>
      </tt:RelativeZoomTranslationSpace>
      <tt:ContinuousPanTiltVelocitySpace>
        <tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:URI>
        <tt:XRange>
          <tt:Min>-1.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:XRange>
        <tt:YRange>
          <tt:Min>-1.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:YRange>
      </tt:ContinuousPanTiltVelocitySpace>
      <tt:ContinuousZoomVelocitySpace>
        <tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:URI>
        <tt:XRange>
          <tt:Min>-1.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:XRange>
      </tt:ContinuousZoomVelocitySpace>
      <tt:PanTiltSpeedSpace>
        <tt:URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace</tt:URI>
        <tt:XRange>
          <tt:Min>0.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:XRange>
      </tt:PanTiltSpeedSpace>
      <tt:ZoomSpeedSpace>
        <tt:URI>http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace</tt:URI>
        <tt:XRange>
          <tt:Min>0.0</tt:Min>
          <tt:Max>1.0</tt:Max>
        </tt:XRange>
      </tt:ZoomSpeedSpace>
    </tt:Spaces>
    <tt:PTZTimeout>
      <tt:Min>PT0S</tt:Min>
      <tt:Max>PT60S</tt:Max>
    </tt:PTZTimeout>
  </tptz:PTZConfigurationOptions>
</tptz:GetConfigurationOptionsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/GetConfigurationOptionsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting PTZ configuration options: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting PTZ configuration options: {str(e)}")

    def _handle_get_ptz_status(self, request: ET.Element) -> str:
        """
        Handle GetStatus request.
        Returns the PTZ status.
        """
        try:
            # Extract profile token
            get_status = request.find('.//tptz:GetStatus', NAMESPACES)

            if get_status is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetStatus element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = get_status.find('.//tptz:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Update the current time
            self.ptz_status['utcTime'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # Generate response with status
            pan = self.ptz_status['position']['x']
            tilt = self.ptz_status['position']['y']
            zoom = self.ptz_status['position']['z']
            pan_tilt_status = self.ptz_status['moveStatus']['panTilt']
            zoom_status = self.ptz_status['moveStatus']['zoom']
            error = self.ptz_status['error']
            utc_time = self.ptz_status['utcTime']

            response = f"""
<tptz:GetStatusResponse>
  <tptz:PTZStatus>
    <tt:Position>
      <tt:PanTilt x="{pan}" y="{tilt}" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace"/>
      <tt:Zoom x="{zoom}" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace"/>
    </tt:Position>
    <tt:MoveStatus>
      <tt:PanTilt>{pan_tilt_status}</tt:PanTilt>
      <tt:Zoom>{zoom_status}</tt:Zoom>
    </tt:MoveStatus>
    <tt:Error>{error}</tt:Error>
    <tt:UtcTime>{utc_time}</tt:UtcTime>
  </tptz:PTZStatus>
</tptz:GetStatusResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/GetStatusResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting PTZ status: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting PTZ status: {str(e)}")

    def _handle_get_profiles(self, request: ET.Element) -> str:
        """
        Handle GetProfiles request with enhanced profile configuration.
        Returns information about all available profiles with Profile S compliant configuration.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        logger.info("Handling GetProfiles request")
        try:
            # Fetch or generate profiles
            if hasattr(self, 'media_profiles') and self.media_profiles:
                profiles = []
                for profile in self.media_profiles:
                    if hasattr(profile, 'to_dict'):
                        profiles.append(profile.to_dict())
                    else:
                        profiles.append(profile)
                logger.debug(f"Using {len(profiles)} profiles from media_profiles attribute")
            else:
                # Default profiles with config-based values
                base_width = self.config.get("width", 1920)
                base_height = self.config.get("height", 1080)
                base_fps = self.config.get("frame_rate", 6)
                base_bitrate = self.config.get("bitrate", 4000)
                profiles = [
                    {
                        "token": "profile1",
                        "name": "YoLink Main Stream",
                        "resolution": {"width": base_width, "height": base_height},
                        "fps": base_fps,
                        "encoding": "H264",
                        "gop": self.config.get("gop", 30),
                        "bitrate": base_bitrate,
                        "quality": self.config.get("quality", 5)
                    },
                    {
                        "token": "profile2",
                        "name": "YoLink Low Stream",
                        "resolution": {"width": base_width // 2, "height": base_height // 2},
                        "fps": min(base_fps, 4),
                        "encoding": "H264",
                        "gop": self.config.get("gop", 30),
                        "bitrate": base_bitrate // 2,
                        "quality": self.config.get("quality", 5)
                    },
                    {
                        "token": "profile3",
                        "name": "YoLink Mobile Stream",
                        "resolution": {"width": base_width // 4, "height": base_height // 4},
                        "fps": 2,
                        "encoding": "H264",
                        "gop": self.config.get("gop", 30),
                        "bitrate": base_bitrate // 4,
                        "quality": self.config.get("quality", 5)
                    }
                ]
                logger.debug("Generated default profiles")

            # Build profiles XML dynamically
            profiles_xml = ""
            for profile in profiles:
                token = profile.get("token", "unknown")
                name = profile.get("name", f"Profile_{token}")
                resolution = profile.get("resolution", {"width": 1920, "height": 1080})
                width = resolution.get("width", 1920)
                height = resolution.get("height", 1080)
                fps = profile.get("fps", 6)
                encoding = profile.get("encoding", "H264")
                gop = profile.get("gop", 30)
                bitrate = profile.get("bitrate", 4000)
                quality = profile.get("quality", 5)

                # Determine H264 profile based on resolution
                h264_profile = "High" if width > 1280 or height > 720 else "Main" if width > 640 or height > 480 else "Baseline"

                # Profile S compliant XML
                profiles_xml += f"""
    <trt:Profiles fixed="true" token="{token}">
      <tt:Name>{name}</tt:Name>
      <tt:VideoSourceConfiguration token="VideoSourceConfig_{token}">
        <tt:Name>VideoSourceConfig_{token}</tt:Name>
        <tt:UseCount>1</tt:UseCount>
        <tt:SourceToken>VideoSource</tt:SourceToken>
        <tt:Bounds height="{height}" width="{width}" y="0" x="0"/>
      </tt:VideoSourceConfiguration>
      <tt:VideoEncoderConfiguration token="VideoEncoder_{token}">
        <tt:Name>VideoEncoder_{token}</tt:Name>
        <tt:UseCount>1</tt:UseCount>
        <tt:Encoding>{encoding}</tt:Encoding>
        <tt:Resolution>
          <tt:Width>{width}</tt:Width>
          <tt:Height>{height}</tt:Height>
        </tt:Resolution>
        <tt:Quality>{quality}</tt:Quality>
        <tt:RateControl>
          <tt:FrameRateLimit>{fps}</tt:FrameRateLimit>
          <tt:EncodingInterval>1</tt:EncodingInterval>
          <tt:BitrateLimit>{bitrate}</tt:BitrateLimit>
        </tt:RateControl>
        <tt:H264>
          <tt:GovLength>{gop}</tt:GovLength>
          <tt:H264Profile>{h264_profile}</tt:H264Profile>
        </tt:H264>
        <tt:Multicast>
          <tt:Address>
            <tt:Type>IPv4</tt:Type>
            <tt:IPv4Address>224.0.0.0</tt:IPv4Address>
          </tt:Address>
          <tt:Port>0</tt:Port>
          <tt:TTL>1</tt:TTL>
          <tt:AutoStart>false</tt:AutoStart>
        </tt:Multicast>
        <tt:SessionTimeout>PT60S</tt:SessionTimeout>
      </tt:VideoEncoderConfiguration>
      <tt:MetadataConfiguration token="MetadataConfig_{token}">
        <tt:Name>MetadataConfig_{token}</tt:Name>
        <tt:UseCount>1</tt:UseCount>
        <tt:Analytics>false</tt:Analytics>
        <tt:Multicast>
          <tt:Address>
            <tt:Type>IPv4</tt:Type>
            <tt:IPv4Address>224.0.0.0</tt:IPv4Address>
          </tt:Address>
          <tt:Port>0</tt:Port>
          <tt:TTL>1</tt:TTL>
          <tt:AutoStart>false</tt:AutoStart>
        </tt:Multicast>
        <tt:SessionTimeout>PT60S</tt:SessionTimeout>
      </tt:MetadataConfiguration>
    </trt:Profiles>
    """
            # Log the generated profiles for diagnostics
            logger.debug(f"Generated profiles XML: {profiles_xml[:500]}...")

            response = f"<trt:GetProfilesResponse>{profiles_xml}</trt:GetProfilesResponse>"
            return generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse",
                response
            )

        except Exception as e:
            logger.error(f"Error handling GetProfiles: {e}", exc_info=True)
            return generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError")



    def _handle_get_presets(self, request: ET.Element) -> str:
        """
        Handle GetPresets request.
        Returns the PTZ presets (not actually implemented).
        """
        try:
            # Extract profile token
            get_presets = request.find('.//tptz:GetPresets', NAMESPACES)

            if get_presets is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetPresets element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = get_presets.find('.//tptz:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Generate response with presets
            # For this minimal implementation, just return two fake presets
            response = f"""
<tptz:GetPresetsResponse>
  <tptz:Preset token="1">
    <tt:Name>Home</tt:Name>
    <tt:PTZPosition>
      <tt:PanTilt x="0.0" y="0.0" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace"/>
      <tt:Zoom x="0.0" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace"/>
    </tt:PTZPosition>
  </tptz:Preset>
  <tptz:Preset token="2">
    <tt:Name>Default</tt:Name>
    <tt:PTZPosition>
      <tt:PanTilt x="0.5" y="0.5" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace"/>
      <tt:Zoom x="0.5" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace"/>
    </tt:PTZPosition>
  </tptz:Preset>
</tptz:GetPresetsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/GetPresetsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting PTZ presets: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting PTZ presets: {str(e)}")

    def _handle_goto_preset(self, request: ET.Element) -> str:
        """
        Handle GotoPreset request.
        Moves to a PTZ preset (not actually implemented).
        """
        try:
            # Extract parameters
            goto_preset = request.find('.//tptz:GotoPreset', NAMESPACES)

            if goto_preset is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GotoPreset element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = goto_preset.find('.//tptz:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            preset_token_elem = goto_preset.find('.//tptz:PresetToken', NAMESPACES)
            if preset_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing PresetToken",
                    "ter:InvalidArgVal"
                )

            preset_token = preset_token_elem.text

            # In a real implementation, you would move to the preset here

            # Update status to show movement
            self.ptz_status['moveStatus']['panTilt'] = 'MOVING'
            self.ptz_status['moveStatus']['zoom'] = 'MOVING'
            self.ptz_status['utcTime'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # For fake implementation, update position based on preset
            if preset_token == "1":  # Home
                self.ptz_status['position']['x'] = 0.0
                self.ptz_status['position']['y'] = 0.0
                self.ptz_status['position']['z'] = 0.0
            elif preset_token == "2":  # Default
                self.ptz_status['position']['x'] = 0.5
                self.ptz_status['position']['y'] = 0.5
                self.ptz_status['position']['z'] = 0.5

            # In a real implementation, the status would be updated when movement completes
            # We'll simulate that by setting status back to idle
            self.ptz_status['moveStatus']['panTilt'] = 'IDLE'
            self.ptz_status['moveStatus']['zoom'] = 'IDLE'

            # Generate response
            response = """
<tptz:GotoPresetResponse>
</tptz:GotoPresetResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/GotoPresetResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error moving to preset: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error moving to preset: {str(e)}")

    def _handle_continuous_move(self, request: ET.Element) -> str:
        """
        Handle ContinuousMove request.
        Starts a continuous PTZ movement (not actually implemented).
        """
        try:
            # Extract parameters
            continuous_move = request.find('.//tptz:ContinuousMove', NAMESPACES)

            if continuous_move is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ContinuousMove element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = continuous_move.find('.//tptz:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Extract velocity if provided
            velocity_elem = continuous_move.find('.//tptz:Velocity', NAMESPACES)

            # Update status to show movement
            self.ptz_status['moveStatus']['panTilt'] = 'MOVING'
            self.ptz_status['moveStatus']['zoom'] = 'MOVING'
            self.ptz_status['utcTime'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # In a real implementation, you would start continuous movement here

            # Generate response
            response = """
<tptz:ContinuousMoveResponse>
</tptz:ContinuousMoveResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/ContinuousMoveResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error starting continuous move: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error starting continuous move: {str(e)}")

    def _handle_relative_move(self, request: ET.Element) -> str:
        """
        Handle RelativeMove request.
        Performs a relative PTZ movement (not actually implemented).
        """
        try:
            # Extract parameters
            relative_move = request.find('.//tptz:RelativeMove', NAMESPACES)

            if relative_move is None:
                return XMLGenerator.generate_fault_response(
                    "Missing RelativeMove element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = relative_move.find('.//tptz:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Extract translation if provided
            translation_elem = relative_move.find('.//tptz:Translation', NAMESPACES)

            # Update status to show movement
            self.ptz_status['moveStatus']['panTilt'] = 'MOVING'
            self.ptz_status['moveStatus']['zoom'] = 'MOVING'
            self.ptz_status['utcTime'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # In a real implementation, you would perform relative movement here

            # For simulation, set status back to idle
            self.ptz_status['moveStatus']['panTilt'] = 'IDLE'
            self.ptz_status['moveStatus']['zoom'] = 'IDLE'

            # Generate response
            response = """
<tptz:RelativeMoveResponse>
</tptz:RelativeMoveResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/RelativeMoveResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error performing relative move: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error performing relative move: {str(e)}")

    def _handle_absolute_move(self, request: ET.Element) -> str:
        """
        Handle AbsoluteMove request.
        Performs an absolute PTZ movement (not actually implemented).
        """
        try:
            # Extract parameters
            absolute_move = request.find('.//tptz:AbsoluteMove', NAMESPACES)

            if absolute_move is None:
                return XMLGenerator.generate_fault_response(
                    "Missing AbsoluteMove element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = absolute_move.find('.//tptz:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Extract position if provided
            position_elem = absolute_move.find('.//tptz:Position', NAMESPACES)

            if position_elem is not None:
                # Extract pan/tilt position
                pan_tilt_elem = position_elem.find('.//tt:PanTilt', NAMESPACES)
                if pan_tilt_elem is not None:
                    try:
                        pan = float(pan_tilt_elem.get('x', 0.0))
                        tilt = float(pan_tilt_elem.get('y', 0.0))

                        # Constrain values to valid range
                        pan = max(-1.0, min(1.0, pan))
                        tilt = max(-1.0, min(1.0, tilt))

                        self.ptz_status['position']['x'] = pan
                        self.ptz_status['position']['y'] = tilt
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Error parsing PanTilt values: {e}")

                # Extract zoom position
                zoom_elem = position_elem.find('.//tt:Zoom', NAMESPACES)
                if zoom_elem is not None:
                    try:
                        zoom = float(zoom_elem.get('x', 0.0))

                        # Constrain value to valid range
                        zoom = max(0.0, min(1.0, zoom))

                        self.ptz_status['position']['z'] = zoom
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Error parsing Zoom value: {e}")

            # Update status to show movement
            self.ptz_status['moveStatus']['panTilt'] = 'MOVING'
            self.ptz_status['moveStatus']['zoom'] = 'MOVING'
            self.ptz_status['utcTime'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # In a real implementation, you would perform absolute movement here

            # For simulation, set status back to idle
            self.ptz_status['moveStatus']['panTilt'] = 'IDLE'
            self.ptz_status['moveStatus']['zoom'] = 'IDLE'

            # Generate response
            response = """
<tptz:AbsoluteMoveResponse>
</tptz:AbsoluteMoveResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/AbsoluteMoveResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error performing absolute move: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error performing absolute move: {str(e)}")

    def _handle_ptz_stop(self, request: ET.Element) -> str:
        """
        Handle Stop request.
        Stops PTZ movement (not actually implemented).
        """
        try:
            # Extract parameters
            stop = request.find('.//tptz:Stop', NAMESPACES)

            if stop is None:
                return XMLGenerator.generate_fault_response(
                    "Missing Stop element",
                    "ter:InvalidArgVal"
                )

            profile_token_elem = stop.find('.//tptz:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Update status to show stop
            self.ptz_status['moveStatus']['panTilt'] = 'IDLE'
            self.ptz_status['moveStatus']['zoom'] = 'IDLE'
            self.ptz_status['utcTime'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # In a real implementation, you would stop PTZ movement here

            # Generate response
            response = """
<tptz:StopResponse>
</tptz:StopResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver20/ptz/wsdl/StopResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error stopping PTZ movement: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error stopping PTZ movement: {str(e)}")

    #
    # Media service handlers (additional ones for Profile S compliance)
    #
    def _handle_get_guaranteed_number_of_video_encoder_instances(self, request: ET.Element) -> str:
        """
        Handle GetGuaranteedNumberOfVideoEncoderInstances request.
        Returns the number of concurrent encoding instances supported.
        """
        try:
            # Extract parameters
            get_instances = request.find('.//trt:GetGuaranteedNumberOfVideoEncoderInstances', NAMESPACES)

            if get_instances is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetGuaranteedNumberOfVideoEncoderInstances element",
                    "ter:InvalidArgVal"
                )

            # Extract configuration token if provided
            config_token = None
            config_token_elem = get_instances.find('.//trt:ConfigurationToken', NAMESPACES)
            if config_token_elem is not None:
                config_token = config_token_elem.text

            # Generate response
            response = """
<trt:GetGuaranteedNumberOfVideoEncoderInstancesResponse>
  <trt:TotalNumber>3</trt:TotalNumber>
  <trt:H264>3</trt:H264>
  <trt:MPEG4>0</trt:MPEG4>
  <trt:JPEG>0</trt:JPEG>
</trt:GetGuaranteedNumberOfVideoEncoderInstancesResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetGuaranteedNumberOfVideoEncoderInstancesResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting guaranteed encoder instances: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting guaranteed encoder instances: {str(e)}")

    def _handle_start_multicast_streaming(self, request: ET.Element) -> str:
        """
        Handle StartMulticastStreaming request.
        Starts multicast streaming (not actually implemented).
        """
        try:
            # Extract parameters
            start_multicast = request.find('.//trt:StartMulticastStreaming', NAMESPACES)

            if start_multicast is None:
                return XMLGenerator.generate_fault_response(
                    "Missing StartMulticastStreaming element",
                    "ter:InvalidArgVal"
                )

            # Extract profile token
            profile_token_elem = start_multicast.find('.//trt:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Since we don't support multicast, return an error
            return XMLGenerator.generate_fault_response(
                "Multicast streaming not supported",
                "ter:ActionNotSupported"
            )
        except Exception as e:
            logger.error(f"Error starting multicast streaming: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error starting multicast streaming: {str(e)}")

    def _handle_stop_multicast_streaming(self, request: ET.Element) -> str:
        """
        Handle StopMulticastStreaming request.
        Stops multicast streaming (not actually implemented).
        """
        try:
            # Extract parameters
            stop_multicast = request.find('.//trt:StopMulticastStreaming', NAMESPACES)

            if stop_multicast is None:
                return XMLGenerator.generate_fault_response(
                    "Missing StopMulticastStreaming element",
                    "ter:InvalidArgVal"
                )

            # Extract profile token
            profile_token_elem = stop_multicast.find('.//trt:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # Since we don't support multicast, return an error
            return XMLGenerator.generate_fault_response(
                "Multicast streaming not supported",
                "ter:ActionNotSupported"
            )
        except Exception as e:
            logger.error(f"Error stopping multicast streaming: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error stopping multicast streaming: {str(e)}")

    def _handle_get_osds(self, request: ET.Element) -> str:
        """
        Handle GetOSDs request.
        Returns the on-screen displays (not actually implemented).
        """
        try:
            # Extract parameters
            get_osds = request.find('.//trt:GetOSDs', NAMESPACES)

            if get_osds is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetOSDs element",
                    "ter:InvalidArgVal"
                )

            # Generate empty response - we don't support OSDs
            response = """
<trt:GetOSDsResponse>
</trt:GetOSDsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetOSDsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting OSDs: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting OSDs: {str(e)}")

    def _handle_get_osd_options(self, request: ET.Element) -> str:
        """
        Handle GetOSDOptions request.
        Returns the OSD options (not actually implemented).
        """
        try:
            # Extract parameters
            get_osd_options = request.find('.//trt:GetOSDOptions', NAMESPACES)

            if get_osd_options is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetOSDOptions element",
                    "ter:InvalidArgVal"
                )

            # Generate response with minimal options
            response = """
<trt:GetOSDOptionsResponse>
  <trt:OSDOptions>
    <tt:MaximumNumberOfOSDs Total="0">
      <tt:PlainText>0</tt:PlainText>
      <tt:Date>0</tt:Date>
      <tt:Time>0</tt:Time>
      <tt:DateAndTime>0</tt:DateAndTime>
      <tt:Image>0</tt:Image>
    </tt:MaximumNumberOfOSDs>
  </trt:OSDOptions>
</trt:GetOSDOptionsResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetOSDOptionsResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting OSD options: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting OSD options: {str(e)}")

    def _handle_set_osd(self, request: ET.Element) -> str:
        """
        Handle SetOSD request.
        Sets an on-screen display (not actually implemented).
        """
        try:
            # Extract parameters
            set_osd = request.find('.//trt:SetOSD', NAMESPACES)

            if set_osd is None:
                return XMLGenerator.generate_fault_response(
                    "Missing SetOSD element",
                    "ter:InvalidArgVal"
                )

            # Return error since we don't support OSDs
            return XMLGenerator.generate_fault_response(
                "OSD not supported",
                "ter:ActionNotSupported"
            )
        except Exception as e:
            logger.error(f"Error setting OSD: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error setting OSD: {str(e)}")

    def _handle_set_synchronization_point(self, request: ET.Element) -> str:
        """
        Handle SetSynchronizationPoint request for media service.
        Requests a synchronization point in the media streams.
        """
        try:
            # Extract parameters
            set_sync_point = request.find('.//trt:SetSynchronizationPoint', NAMESPACES)

            if set_sync_point is None:
                return XMLGenerator.generate_fault_response(
                    "Missing SetSynchronizationPoint element",
                    "ter:InvalidArgVal"
                )

            # Extract profile token
            profile_token_elem = set_sync_point.find('.//trt:ProfileToken', NAMESPACES)
            if profile_token_elem is None:
                return XMLGenerator.generate_fault_response(
                    "Missing ProfileToken",
                    "ter:InvalidArgVal"
                )

            profile_token = profile_token_elem.text

            # In a real implementation, you would request an I-frame in the video stream

            # Generate response
            response = """
<trt:SetSynchronizationPointResponse>
</trt:SetSynchronizationPointResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/SetSynchronizationPointResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error setting synchronization point: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error setting synchronization point: {str(e)}")

    #
    # Device service handlers (additional ones for Profile S compliance)
    #
    def _handle_get_discovery_mode(self, request: ET.Element) -> str:
        """
        Handle GetDiscoveryMode request.
        Returns the discovery mode.
        """
        try:
            response = """
<tds:GetDiscoveryModeResponse>
  <tds:DiscoveryMode>Discoverable</tds:DiscoveryMode>
</tds:GetDiscoveryModeResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetDiscoveryModeResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting discovery mode: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting discovery mode: {str(e)}")

    def _handle_get_dns(self, request: ET.Element) -> str:
        """
        Handle GetDNS request.
        Returns the DNS settings.
        """
        try:
            response = """
<tds:GetDNSResponse>
  <tds:DNSInformation>
    <tt:FromDHCP>false</tt:FromDHCP>
    <tt:DNSManual>
      <tt:Type>IPv4</tt:Type>
      <tt:IPv4Address>8.8.8.8</tt:IPv4Address>
    </tt:DNSManual>
  </tds:DNSInformation>
</tds:GetDNSResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetDNSResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting DNS: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting DNS: {str(e)}")

    def _handle_get_dynamic_dns(self, request: ET.Element) -> str:
        """
        Handle GetDynamicDNS request.
        Returns the dynamic DNS settings.
        """
        try:
            response = """
<tds:GetDynamicDNSResponse>
  <tds:DynamicDNSInformation>
    <tt:Type>NoUpdate</tt:Type>
  </tds:DynamicDNSInformation>
</tds:GetDynamicDNSResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetDynamicDNSResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting dynamic DNS: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting dynamic DNS: {str(e)}")

    def _handle_get_users(self, request: ET.Element) -> str:
        """
        Handle GetUsers request.
        Returns the list of users.
        """
        try:
            response = f"""
<tds:GetUsersResponse>
  <tds:User>
    <tt:Username>{self.username}</tt:Username>
    <tt:UserLevel>Administrator</tt:UserLevel>
  </tds:User>
</tds:GetUsersResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetUsersResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting users: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting users: {str(e)}")

    def _handle_get_wsdl_url(self, request: ET.Element) -> str:
        """
        Handle GetWsdlUrl request.
        Returns the WSDL URL.
        """
        try:
            response = """
<tds:GetWsdlUrlResponse>
  <tds:WsdlUrl>https://www.onvif.org/onvif/ver10/device/wsdl/devicemgmt.wsdl</tds:WsdlUrl>
</tds:GetWsdlUrlResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetWsdlUrlResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting WSDL URL: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting WSDL URL: {str(e)}")

    def _handle_get_system_log(self, request: ET.Element) -> str:
        """
        Handle GetSystemLog request.
        Returns system log information.
        """
        try:
            # Extract parameters
            get_system_log = request.find('.//tds:GetSystemLog', NAMESPACES)

            if get_system_log is None:
                return XMLGenerator.generate_fault_response(
                    "Missing GetSystemLog element",
                    "ter:InvalidArgVal"
                )

            # Minimal log response
            response = """
<tds:GetSystemLogResponse>
  <tds:SystemLog>
    <tt:String>
No log entries available.
    </tt:String>
  </tds:SystemLog>
</tds:GetSystemLogResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetSystemLogResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting system log: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting system log: {str(e)}")

    def _handle_get_system_support_information(self, request: ET.Element) -> str:
        """
        Handle GetSystemSupportInformation request.
        Returns system support information.
        """
        try:
            response = f"""
<tds:GetSystemSupportInformationResponse>
  <tds:SupportInformation>
    <tt:String>
Device Model: {self.device_info['Model']}
Manufacturer: {self.device_info['Manufacturer']}
Firmware Version: {self.device_info['FirmwareVersion']}
Serial Number: {self.device_info['SerialNumber']}
Hardware ID: {self.device_info['HardwareId']}
    </tt:String>
  </tds:SupportInformation>
</tds:GetSystemSupportInformationResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetSystemSupportInformationResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting system support information: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting system support information: {str(e)}")

    def _handle_get_system_backup(self, request: ET.Element) -> str:
        """
        Handle GetSystemBackup request.
        Returns system backup files (not actually implemented).
        """
        try:
            response = """
<tds:GetSystemBackupResponse>
</tds:GetSystemBackupResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetSystemBackupResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error getting system backup: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error getting system backup: {str(e)}")

    def _handle_system_reboot(self, request: ET.Element) -> str:
        """
        Handle SystemReboot request.
        Reboots the device (not actually implemented).
        """
        try:
            response = """
<tds:SystemRebootResponse>
  <tds:Message>System will reboot in 5 seconds</tds:Message>
</tds:SystemRebootResponse>
"""
            return XMLGenerator.generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/SystemRebootResponse",
                response
            )
        except Exception as e:
            logger.error(f"Error handling system reboot: {e}", exc_info=True)
            return XMLGenerator.generate_fault_response(f"Error handling system reboot: {str(e)}")

    def _handle_get_stream_uri(self, request: ET.Element) -> str:
        """
        Handle GetStreamUri request with support for metadata streams and detailed diagnostics.
        Returns the RTSP URI for a specific profile.

        Args:
            request: Request XML element

        Returns:
            str: SOAP response XML
        """
        logger.info("Processing GetStreamUri request")
        logger.debug(f"Full request XML: {ET.tostring(request, encoding='unicode')}")

        try:
            # Extract GetStreamUri element
            get_stream_uri = request.find('.//trt:GetStreamUri', NAMESPACES)
            if get_stream_uri is None:
                logger.error("Missing GetStreamUri element in request")
                return generate_fault_response("Missing GetStreamUri element", "ter:InvalidArgVal")

            # Extract profile token
            profile_token_elem = get_stream_uri.find('.//trt:ProfileToken', NAMESPACES)
            if profile_token_elem is None or not profile_token_elem.text:
                logger.error("Missing or empty ProfileToken in request")
                return generate_fault_response("Missing ProfileToken", "ter:InvalidArgVal")
            profile_token = profile_token_elem.text
            logger.info(f"Profile token requested: {profile_token}")

            # Extract stream setup details
            stream_setup = get_stream_uri.find('.//trt:StreamSetup', NAMESPACES)
            if stream_setup is None:
                logger.error("Missing StreamSetup in request")
                return generate_fault_response("Missing StreamSetup", "ter:InvalidArgVal")

            # Check stream type
            stream_type_elem = stream_setup.find('.//tt:Stream', NAMESPACES)
            stream_type = stream_type_elem.text if stream_type_elem is not None else "RTP-Unicast"
            is_metadata = stream_type == "Metadata"
            logger.debug(f"Stream type: {stream_type}, is_metadata: {is_metadata}")

            # Get transport protocol
            transport_elem = stream_setup.find('.//tt:Transport/tt:Protocol', NAMESPACES)
            transport = transport_elem.text if transport_elem is not None else "RTSP"
            logger.debug(f"Transport protocol: {transport}")

            # Try integration layer
            if hasattr(self, 'onvif_integration') and self.onvif_integration:
                uri = self.onvif_integration.get_stream_uri(profile_token)
                if uri:
                    logger.info(f"Integration layer returned URI: {uri}")
                    return self._generate_stream_uri_response(uri, is_metadata)
                else:
                    logger.warning(f"Integration layer failed to provide URI for profile {profile_token}")

            # Fallback to manual URI construction
            server_ip = self.config.get("server_ip", "127.0.0.1")
            rtsp_port = self.config.get("rtsp_port", 554)
            stream_name = self.config.get("stream_name", "yolink-dashboard")
            logger.debug(f"Config values - server_ip: {server_ip}, rtsp_port: {rtsp_port}, stream_name: {stream_name}")

            # Profile token mapping
            profile_suffix_map = {
                "profile1": "_main",
                "profile2": "_sub",
                "profile3": "_mobile"
            }
            stream_suffix = profile_suffix_map.get(profile_token, "")
            if not stream_suffix:
                logger.warning(f"Unknown profile token '{profile_token}', using base stream name")

            stream_name = f"{stream_name}{stream_suffix}"
            if is_metadata:
                stream_name = f"{stream_name}_metadata"

            # Authentication
            auth_part = ""
            if getattr(self, 'authentication_required', False):
                auth_part = f"{self.username}:{self.password}@"
                logger.debug(f"Authentication applied: {auth_part}")

            # Construct URI
            if transport == "HTTP":
                uri = f"http://{auth_part}{server_ip}:{rtsp_port}/{stream_name}"
            else:
                uri = f"rtsp://{auth_part}{server_ip}:{rtsp_port}/{stream_name}"
            logger.info(f"Constructed URI: {uri}")

            return self._generate_stream_uri_response(uri, is_metadata)

        except Exception as e:
            logger.error(f"Error in GetStreamUri: {e}", exc_info=True)
            return generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError")

    def _generate_stream_uri_response(self, uri: str, is_metadata: bool) -> str:
        """
        Generate the SOAP response for a GetStreamUri request.
        """
        logger.debug(f"Generating response for URI: {uri}, is_metadata: {is_metadata}")
        response_body = f"""
    <trt:GetStreamUriResponse>
      <trt:MediaUri>
        <tt:Uri>{uri}</tt:Uri>
        <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
        <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
        <tt:Timeout>PT60S</tt:Timeout>
      </trt:MediaUri>
    </trt:GetStreamUriResponse>
    """
        return generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
            response_body
        )


    def _generate_stream_uri_response(self, uri: str, is_metadata: bool) -> str:
        """
        Generate the SOAP response for a GetStreamUri request.

        Args:
            uri: The stream URI to include in the response
            is_metadata: Whether this is a metadata stream

        Returns:
            str: SOAP response XML
        """
        response_body = f"""
    <trt:GetStreamUriResponse>
      <trt:MediaUri>
        <tt:Uri>{uri}</tt:Uri>
        <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
        <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
        <tt:Timeout>PT60S</tt:Timeout>
      </trt:MediaUri>
    </trt:GetStreamUriResponse>
    """
        return generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
            response_body
        )

    def _generate_stream_uri_response(self, uri: str, is_metadata: bool) -> str:
        """
        Generate the SOAP response for a GetStreamUri request.

        Args:
            uri: The stream URI to include in the response
            is_metadata: Whether this is a metadata stream

        Returns:
            str: SOAP response XML
        """
        response_body = f"""
    <trt:GetStreamUriResponse>
      <trt:MediaUri>
        <tt:Uri>{uri}</tt:Uri>
        <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
        <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
        <tt:Timeout>PT60S</tt:Timeout>
      </trt:MediaUri>
    </trt:GetStreamUriResponse>
    """
        return generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
            response_body
        )
    def _handle_get_service_capabilities(self, request: ET.Element, service_type: str) -> str:
        """
        Handle GetServiceCapabilities request for different services.

        Args:
            request: Request XML root
            service_type: Type of service ('device', 'media', 'events', 'imaging', 'ptz')

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
        elif service_type == 'events':
            response = """
<tev:GetServiceCapabilitiesResponse>
  <tev:Capabilities>
    <tev:WSSubscriptionPolicySupport>false</tev:WSSubscriptionPolicySupport>
    <tev:WSPullPointSupport>true</tev:WSPullPointSupport>
    <tev:WSPausableSubscriptionManagerInterfaceSupport>false</tev:WSPausableSubscriptionManagerInterfaceSupport>
    <tev:MaxNotificationProducers>1</tev:MaxNotificationProducers>
    <tev:MaxPullPoints>10</tev:MaxPullPoints>
    <tev:PersistentNotificationStorage>false</tev:PersistentNotificationStorage>
  </tev:Capabilities>
</tev:GetServiceCapabilitiesResponse>
"""
            action = "http://www.onvif.org/ver10/events/wsdl/GetServiceCapabilitiesResponse"
        elif service_type == 'imaging':
            response = """
<timg:GetServiceCapabilitiesResponse>
  <timg:Capabilities>
    <timg:ImageStabilization>false</timg:ImageStabilization>
  </timg:Capabilities>
</timg:GetServiceCapabilitiesResponse>
"""
            action = "http://www.onvif.org/ver20/imaging/wsdl/GetServiceCapabilitiesResponse"
        elif service_type == 'ptz':
            response = """
<tptz:GetServiceCapabilitiesResponse>
  <tptz:Capabilities EFlip="false" Reverse="false" GetCompatibleConfigurations="true" MoveStatus="true" StatusPosition="true" />
</tptz:GetServiceCapabilitiesResponse>
"""
            action = "http://www.onvif.org/ver20/ptz/wsdl/GetServiceCapabilitiesResponse"
        else:
            return XMLGenerator.generate_fault_response(f"Unknown service type: {service_type}")

        return XMLGenerator.generate_soap_response(action, response)

    def _generate_stream_uri_response(self, uri: str, is_metadata: bool = False) -> str:
        """
        Generate a SOAP response for GetStreamUri with optional metadata indicator.

        Args:
            uri: Stream URI
            is_metadata: Flag indicating if this is a metadata stream

        Returns:
            str: SOAP response XML
        """
        response = f"""
    <trt:GetStreamUriResponse>
      <trt:MediaUri>
        <tt:Uri>{uri}</tt:Uri>
        <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
        <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
        <tt:Timeout>PT60S</tt:Timeout>
      </trt:MediaUri>
    </trt:GetStreamUriResponse>
    """
        return XMLGenerator.generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
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
        <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/{self.device_info['Model']} onvif://www.onvif.org/location/Dashboard onvif://www.onvif.org/hardware/{self.device_uuid}</d:Scopes>
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
      <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/{self.device_info['Model']} onvif://www.onvif.org/location/Dashboard onvif://www.onvif.org/hardware/{self.device_uuid}</d:Scopes>
      <d:XAddrs>{self.device_service_url} {self.media_service_url}</d:XAddrs>
      <d:MetadataVersion>1</d:MetadataVersion>
    </d:Bye>
  </s:Body>
</s:Envelope>
"""

    def _cleanup(self) -> None:
        """Clean up resources when stopping the service."""
        logger.info("Cleaning up ONVIF service resources")

        # Announce that we're going offline
        try:
            if self.discovery_socket:
                bye_message = self._generate_bye_message()
                self.discovery_socket.sendto(bye_message.encode('utf-8'), ('239.255.255.250', 3702))
                logger.info("Sent WS-Discovery Bye announcement")
        except Exception as e:
            logger.error(f"Error sending Bye announcement: {e}")

        # Close discovery socket
        if self.discovery_socket:
            try:
                self.discovery_socket.close()
            except Exception as e:
                logger.error(f"Error closing discovery socket: {e}")
            self.discovery_socket = None

        # Shutdown HTTP server
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

        # Send Bye message before closing socket
        if self.discovery_socket:
            try:
                bye_message = self._generate_bye_message()
                self.discovery_socket.sendto(bye_message.encode('utf-8'), ('239.255.255.250', 3702))
                logger.info("Sent WS-Discovery Bye announcement")
            except Exception as e:
                logger.error(f"Error sending Bye announcement: {e}")

        self._cleanup()