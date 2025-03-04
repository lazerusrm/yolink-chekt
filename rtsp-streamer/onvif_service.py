"""
ONVIF service for device discovery and interaction.
Implements WS-Discovery and core ONVIF services.
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
import logging
from typing import Dict, Any, Tuple, Optional, List, Any, Optional, Callable
from urllib.parse import urlparse, parse_qs
import re
import time

logger = logging.getLogger(__name__)

# ONVIF XML namespaces
NS = {
    'soap': 'http://www.w3.org/2003/05/soap-envelope',
    'wsa': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
    'wsd': 'http://schemas.xmlsoap.org/ws/2005/04/discovery',
    'tds': 'http://www.onvif.org/ver10/device/wsdl',
    'trt': 'http://www.onvif.org/ver10/media/wsdl',
    'tt': 'http://www.onvif.org/ver10/schema',
    'wsnt': 'http://docs.oasis-open.org/wsn/b-2',
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
}

# Register namespace prefixes for pretty XML output
for prefix, uri in NS.items():
    ET.register_namespace(prefix, uri)


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


class OnvifRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP request handler for ONVIF SOAP services.
    """
    server_version = "ONVIF/1.0"
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, service=None, **kwargs):
        self.service = service
        super().__init__(*args, **kwargs)

        # Get attributes from service
        if hasattr(service, 'server_ip') and hasattr(service, 'onvif_port'):
            self.server_ip = service.server_ip
            self.onvif_port = service.onvif_port
        else:
            # Default values or log an error
            logger.error("Service missing required attributes: server_ip or onvif_port")
            self.server_ip = "127.0.0.1"
            self.onvif_port = 8555

        # ONVIF services base URLs
        self.device_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/device_service"
        self.media_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/media_service"
        self.events_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/events_service"

        # WS-Discovery multicast settings
        self.multicast_address = '239.255.255.250'
        self.multicast_port = 3702
        self.multicast_socket = None

        # Thread synchronization
        self.lock = threading.Lock()

        # HTTP server for ONVIF services
        self.http_server = None

    def do_POST(self):
        """Handle ONVIF SOAP POST requests."""
        # Extract content length
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error(400, "Missing request body")
            return

        # Read request body
        soap_request = self.rfile.read(content_length).decode('utf-8')
        logger.debug(f"Received SOAP request: {soap_request}")

        # Check authentication
        if not self._check_authentication(soap_request):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="ONVIF"')
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Authentication required")
            return

        # Parse service path and dispatch to appropriate handler
        service_path = self.path.lower()
        response = ""

        try:
            if '/onvif/device_service' in service_path:
                response = self.service.handle_device_service(soap_request)
            elif '/onvif/media_service' in service_path:
                response = self.service.handle_media_service(soap_request)
            else:
                # Unknown service
                self.send_error(404, "Service not found")
                return

            # Send successful response
            self.send_response(200)
            self.send_header('Content-Type', 'application/soap+xml; charset=utf-8')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))

        except Exception as e:
            logger.error(f"Error handling SOAP request: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")

    def _check_authentication(self, soap_request: str) -> bool:
        """
        Check if the request includes valid authentication.

        Args:
            soap_request: The SOAP request XML

        Returns:
            bool: True if authentication is valid or not required
        """
        if not self.service.authentication_required:
            return True

        # Check for Authorization header for Basic auth
        auth_header = self.headers.get('Authorization')
        if auth_header and auth_header.startswith('Basic '):
            auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            username, password = auth_decoded.split(':', 1)

            if (username == self.service.username and
                password == self.service.password):
                return True

        # Check for WS-Security in SOAP header
        try:
            root = ET.fromstring(soap_request)
            header = root.find('.//soap:Header', NS)
            if header is not None:
                security = header.find('.//wsse:Security', NS)
                if security is not None:
                    username_token = security.find('.//wsse:UsernameToken', NS)
                    if username_token is not None:
                        username_elem = username_token.find('.//wsse:Username', NS)
                        password_elem = username_token.find('.//wsse:Password', NS)

                        if (username_elem is not None and
                            password_elem is not None and
                            username_elem.text == self.service.username):

                            # Check if it's plaintext or digest
                            password_type = password_elem.attrib.get('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Type', '')

                            if 'PasswordDigest' in password_type:
                                # Handle digest authentication
                                nonce_elem = username_token.find('.//wsse:Nonce', NS)
                                created_elem = username_token.find('.//wsu:Created', NS)

                                if nonce_elem is not None and created_elem is not None:
                                    nonce = nonce_elem.text
                                    created = created_elem.text
                                    password_digest = compute_password_digest(
                                        nonce, created, self.service.password)

                                    if password_digest == password_elem.text:
                                        return True
                            else:
                                # Handle plaintext password
                                if password_elem.text == self.service.password:
                                    return True
        except Exception as e:
            logger.error(f"Error checking WS-Security: {e}")

        return False

    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"{self.address_string()} - {format % args}")


class OnvifHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server for ONVIF services."""
    allow_reuse_address = True

    def __init__(self, server_address, service):
        self.service = service
        super().__init__(server_address, self.handler_class)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        self.RequestHandlerClass(request, client_address, self, service=self.service)

    def handler_class(self, *args, **kwargs):
        return OnvifRequestHandler(*args, **kwargs)


class OnvifService(threading.Thread):
    """
    ONVIF service for camera device discovery and interaction.
    Implements WS-Discovery for announcing the RTSP stream as an ONVIF camera.
    """

    def __init__(self, config: Dict[str, Any]):
        self.lock = threading.Lock()
        """
        Initialize the ONVIF service.

        Args:
            config: Application configuration
        """
        super().__init__()
        self.config = config
        self.server_ip = config.get("server_ip")
        self.onvif_port = config.get("onvif_port", 8555)
        self.rtsp_port = config.get("rtsp_port", 8554)
        self.stream_name = config.get("stream_name", "yolink-dashboard")

        # Authentication settings
        self.authentication_required = True
        self.username = config.get("onvif_username", "admin")
        self.password = config.get("onvif_password", "123456")

        # Generate unique device identifiers
        self.device_uuid = str(uuid.uuid4())
        self.device_info = {
            "Manufacturer": "YoLink",
            "Model": "Dashboard-RTSP",
            "FirmwareVersion": "1.0.0",
            "SerialNumber": self.device_uuid,
            "HardwareId": "YOLINK-DASHBOARD-1"
        }

        # RTSP stream URL and media profile info
        self.rtsp_url = f"rtsp://{self.server_ip}:{self.rtsp_port}/{self.stream_name}"
        self.media_profiles = [
            {
                "token": "profile1",
                "name": "YoLink Main Stream",
                "resolution": {"width": 1920, "height": 1080},
                "fps": 30,
                "encoding": "H264"
            }
        ]

        # Thread settings
        self.daemon = True
        self.running = True

        # ONVIF services base URLs
        self.device_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/device_service"
        self.media_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/media_service"
        self.events_service_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/events_service"

        # HTTP server for ONVIF services
        self.http_server = None

    def register_profile_callback(self, callback: Callable[[str], bool]) -> None:
        """
        Register a callback to be called when a profile is requested.

        Args:
            callback: Function to call with profile token when a profile is requested
        """
        self.profile_callback = callback
        logger.info("Profile callback registered")

    def handle_get_stream_uri(self, soap_request: str) -> str:
        """
        Enhanced handler for GetStreamUri request that supports profile selection.

        Args:
            soap_request: SOAP request XML

        Returns:
            str: SOAP response XML
        """
        try:
            # Parse the SOAP request
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NS)

            if body is None:
                return self._generate_fault_response("Invalid SOAP request")

            # Get profile token
            get_stream_uri = body.find('.//trt:GetStreamUri', NS)
            if get_stream_uri is None:
                return self._generate_fault_response("Missing GetStreamUri element")

            profile_token = get_stream_uri.find('.//trt:ProfileToken', NS)
            if profile_token is None:
                return self._generate_fault_response("Missing ProfileToken")

            # Get stream protocol
            protocol = get_stream_uri.find('.//trt:Protocol', NS)
            if protocol is None:
                return self._generate_fault_response("Missing Protocol")

            # Validate profile token
            token = profile_token.text
            found = False
            for profile in self.media_profiles:
                if profile['token'] == token:
                    found = True
                    break

            if not found:
                return self._generate_fault_response(f"Profile not found: {token}")

            # Trigger profile callback if registered
            if hasattr(self, 'profile_callback') and callable(self.profile_callback):
                logger.info(f"Triggering profile callback for token: {token}")
                self.profile_callback(token)

            # Determine stream name based on profile token
            stream_name = self.stream_name
            if token == "profile1":
                stream_name = f"{self.stream_name}_main"
            elif token == "profile2":
                stream_name = f"{self.stream_name}_low"
            elif token == "profile3":
                stream_name = f"{self.stream_name}_mobile"

            # Get auth parameters for RTSP URL if needed
            auth_part = ""
            if self.authentication_required:
                auth_part = f"{self.username}:{self.password}@"

            # Return RTSP URI with appropriate stream name
            stream_url = f"rtsp://{auth_part}{self.server_ip}:{self.rtsp_port}/{stream_name}"

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
            return self._generate_soap_response(
                "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
                response
            )

        except Exception as e:
            logger.error(f"Error handling GetStreamUri request: {e}")
            return self._generate_fault_response(f"Internal error: {str(e)}")

    def run(self) -> None:
        """
        Thread main function. Starts WS-Discovery service and HTTP services.
        """
        logger.info(f"Starting ONVIF service on port {self.onvif_port}")
        logger.info(f"ONVIF device service: {self.device_service_url}")

        # Start HTTP server for ONVIF services
        try:
            self.http_server = OnvifHTTPServer((self.server_ip, self.onvif_port), self)
            http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            http_thread.start()
            logger.info(f"ONVIF HTTP server running on port {self.onvif_port}")
        except Exception as e:
            logger.error(f"Failed to start ONVIF HTTP server: {e}")

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

        # Send initial Hello announcement
        self._send_hello_announcement(sock)

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

    def _send_hello_announcement(self, sock: socket.socket) -> None:
        """
        Send a WS-Discovery Hello announcement to advertise the device.

        Args:
            sock: UDP socket for WS-Discovery
        """
        try:
            hello_msg = self._generate_hello_message()
            sock.sendto(hello_msg.encode(), ('239.255.255.250', 3702))
            logger.info("Sent WS-Discovery Hello announcement")
        except Exception as e:
            logger.error(f"Failed to send Hello announcement: {e}")

    def _generate_hello_message(self) -> str:
        """
        Generate a WS-Discovery Hello message.

        Returns:
            str: SOAP XML Hello message
        """
        return f"""
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</a:Action>
    <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body>
    <d:Hello xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <a:EndpointReference><a:Address>urn:uuid:{self.device_uuid}</a:Address></a:EndpointReference>
      <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
      <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/YoLinkDashboard onvif://www.onvif.org/location/Dashboard</d:Scopes>
      <d:XAddrs>{self.device_service_url}</d:XAddrs>
      <d:MetadataVersion>1</d:MetadataVersion>
    </d:Hello>
  </s:Body>
</s:Envelope>
"""

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
    <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
  </s:Header>
  <s:Body>
    <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <d:ProbeMatch>
        <a:EndpointReference>
          <a:Address>urn:uuid:{self.device_uuid}</a:Address>
        </a:EndpointReference>
        <d:Types xmlns:tds="http://www.onvif.org/ver10/device/wsdl">tds:Device</d:Types>
        <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/YoLinkDashboard onvif://www.onvif.org/location/Dashboard</d:Scopes>
        <d:XAddrs>{self.device_service_url}</d:XAddrs>
        <d:MetadataVersion>1</d:MetadataVersion>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>
"""

    def handle_device_service(self, soap_request: str) -> str:
        """
        Handle ONVIF Device service requests.

        Args:
            soap_request: SOAP request XML

        Returns:
            str: SOAP response XML
        """
        try:
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NS)

            if body is None:
                return self._generate_fault_response("Invalid SOAP request")

            # Extract the action from the request
            action_element = None
            for child in body:
                if child.tag.startswith("{"):
                    action_element = child
                    break

            if action_element is None:
                return self._generate_fault_response("No action element found")

            # Handle different device service actions
            local_name = action_element.tag.split('}')[-1]

            if local_name == 'GetDeviceInformation':
                return self._handle_get_device_information(root)
            elif local_name == 'GetServices':
                return self._handle_get_services(root)
            elif local_name == 'GetCapabilities':
                return self._handle_get_capabilities(root)
            elif local_name == 'GetServiceCapabilities':
                return self._handle_get_service_capabilities(root, 'device')
            elif local_name == 'GetScopes':
                return self._handle_get_scopes(root)
            elif local_name == 'GetSystemDateAndTime':
                return self._handle_get_system_date_and_time(root)
            elif local_name == 'GetHostname':
                return self._handle_get_hostname(root)
            elif local_name == 'GetNetworkInterfaces':
                return self._handle_get_network_interfaces(root)
            elif local_name == 'GetNetworkProtocols':
                return self._handle_get_network_protocols(root)
            else:
                logger.warning(f"Unsupported device service action: {local_name}")
                return self._generate_fault_response(f"Unsupported action: {local_name}")

        except Exception as e:
            logger.error(f"Error handling device service request: {e}")
            return self._generate_fault_response(f"Internal error: {str(e)}")

    def handle_media_service(self, soap_request: str) -> str:
        """
        Handle ONVIF Media service requests.

        Args:
            soap_request: SOAP request XML

        Returns:
            str: SOAP response XML
        """
        try:
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NS)

            if body is None:
                return self._generate_fault_response("Invalid SOAP request")

            # Extract the action from the request
            action_element = None
            for child in body:
                if child.tag.startswith("{"):
                    action_element = child
                    break

            if action_element is None:
                return self._generate_fault_response("No action element found")

            # Handle different media service actions
            local_name = action_element.tag.split('}')[-1]

            if local_name == 'GetProfiles':
                return self._handle_get_profiles(root)
            elif local_name == 'GetProfile':
                return self._handle_get_profile(root)
            elif local_name == 'GetStreamUri':
                return self._handle_get_stream_uri(root)
            elif local_name == 'GetSnapshotUri':
                return self._handle_get_snapshot_uri(root)
            elif local_name == 'GetVideoEncoderConfigurations':
                return self._handle_get_video_encoder_configurations(root)
            elif local_name == 'GetServiceCapabilities':
                return self._handle_get_service_capabilities(root, 'media')
            else:
                logger.warning(f"Unsupported media service action: {local_name}")
                return self._generate_fault_response(f"Unsupported action: {local_name}")

        except Exception as e:
            logger.error(f"Error handling media service request: {e}")
            return self._generate_fault_response(f"Internal error: {str(e)}")

    def _generate_soap_response(self, action: str, body_content: str, msg_id: str = None) -> str:
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

        return f"""
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

    def _generate_fault_response(self, reason: str) -> str:
        """
        Generate a SOAP Fault response.

        Args:
            reason: Fault reason text

        Returns:
            str: SOAP fault XML
        """
        return f"""
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <soap:Fault>
      <soap:Code>
        <soap:Value>soap:Sender</soap:Value>
      </soap:Code>
      <soap:Reason>
        <soap:Text xml:lang="en">{reason}</soap:Text>
      </soap:Reason>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>
"""

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
        return self._generate_soap_response(
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
        return self._generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetServicesResponse",
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
    </tt:Media>
  </tds:Capabilities>
</tds:GetCapabilitiesResponse>
"""
        return self._generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse",
            response
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
  <trt:Capabilities SnapshotUri="true" Rotation="false" VideoSourceMode="false" OSD="false" TemporaryOSDText="false" EXICompression="false" RuleEngine="false" IVASupport="false" ProfileCapabilities="false" MaximumNumberOfProfiles="1" />
</trt:GetServiceCapabilitiesResponse>
"""
            action = "http://www.onvif.org/ver10/media/wsdl/GetServiceCapabilitiesResponse"
        else:
            return self._generate_fault_response(f"Unknown service type: {service_type}")

        return self._generate_soap_response(action, response)

    def _handle_get_profiles(self, request: ET.Element) -> str:
        """
        Handle GetProfiles request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        profiles_xml = ""
        for profile in self.media_profiles:
            profiles_xml += f"""
<trt:Profiles fixed="true" token="{profile['token']}">
  <tt:Name>{profile['name']}</tt:Name>
  <tt:VideoSourceConfiguration token="VideoSourceConfig">
    <tt:Name>VideoSourceConfig</tt:Name>
    <tt:UseCount>1</tt:UseCount>
    <tt:SourceToken>VideoSource</tt:SourceToken>
    <tt:Bounds height="{profile['resolution']['height']}" width="{profile['resolution']['width']}" y="0" x="0"/>
  </tt:VideoSourceConfiguration>
  <tt:VideoEncoderConfiguration token="VideoEncoder">
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
</trt:Profiles>
"""

        response = f"""
<trt:GetProfilesResponse>
{profiles_xml}
</trt:GetProfilesResponse>
"""
        return self._generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse",
            response
        )

    def _handle_get_profile(self, request: ET.Element) -> str:
        """
        Handle GetProfile request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        body = request.find('.//soap:Body', NS)
        if body is None:
            return self._generate_fault_response("Invalid SOAP request")

        get_profile = body.find('.//trt:GetProfile', NS)
        if get_profile is None:
            return self._generate_fault_response("Missing GetProfile element")

        profile_token = get_profile.find('.//trt:ProfileToken', NS)
        if profile_token is None:
            return self._generate_fault_response("Missing ProfileToken")

        token = profile_token.text

        # Find the requested profile
        profile = None
        for p in self.media_profiles:
            if p['token'] == token:
                profile = p
                break

        if profile is None:
            return self._generate_fault_response(f"Profile not found: {token}")

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
    <tt:VideoEncoderConfiguration token="VideoEncoder">
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
  </trt:Profile>
</trt:GetProfileResponse>
"""
        return self._generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetProfileResponse",
            response
        )

    def _handle_get_stream_uri(self, request: ET.Element) -> str:
        """
        Handle GetStreamUri request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        body = request.find('.//soap:Body', NS)
        if body is None:
            return self._generate_fault_response("Invalid SOAP request")

        get_stream_uri = body.find('.//trt:GetStreamUri', NS)
        if get_stream_uri is None:
            return self._generate_fault_response("Missing GetStreamUri element")

        # Get profile token
        profile_token = get_stream_uri.find('.//trt:ProfileToken', NS)
        if profile_token is None:
            return self._generate_fault_response("Missing ProfileToken")

        # Get stream protocol
        protocol = get_stream_uri.find('.//trt:Protocol', NS)
        if protocol is None:
            return self._generate_fault_response("Missing Protocol")

        # Validate profile token
        token = profile_token.text
        found = False
        for profile in self.media_profiles:
            if profile['token'] == token:
                found = True
                break

        if not found:
            return self._generate_fault_response(f"Profile not found: {token}")

        # Get auth parameters for RTSP URL if needed
        auth_part = ""
        if self.authentication_required:
            auth_part = f"{self.username}:{self.password}@"

        # Return RTSP URI
        stream_url = f"rtsp://{auth_part}{self.server_ip}:{self.rtsp_port}/{self.stream_name}"

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
        return self._generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
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
        # For simplicity, we'll just return a mock snapshot URI
        snapshot_url = f"http://{self.server_ip}:{self.onvif_port}/onvif/snapshot"

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
        return self._generate_soap_response(
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
        video_encoders = ""
        for profile in self.media_profiles:
            video_encoders += f"""
<trt:Configurations token="VideoEncoder">
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
        return self._generate_soap_response(
            "http://www.onvif.org/ver10/media/wsdl/GetVideoEncoderConfigurationsResponse",
            response
        )

    def _handle_get_scopes(self, request: ET.Element) -> str:
        """
        Handle GetScopes request.

        Args:
            request: Request XML root

        Returns:
            str: SOAP response XML
        """
        response = """
<tds:GetScopesResponse>
  <tds:Scopes>
    <tt:ScopeDef>Fixed</tt:ScopeDef>
    <tt:ScopeItem>onvif://www.onvif.org/type/video_encoder</tt:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tt:ScopeDef>Fixed</tt:ScopeDef>
    <tt:ScopeItem>onvif://www.onvif.org/type/audio_encoder</tt:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tt:ScopeDef>Fixed</tt:ScopeDef>
    <tt:ScopeItem>onvif://www.onvif.org/hardware/YoLinkDashboard</tt:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tt:ScopeDef>Fixed</tt:ScopeDef>
    <tt:ScopeItem>onvif://www.onvif.org/location/Dashboard</tt:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tt:ScopeDef>Fixed</tt:ScopeDef>
    <tt:ScopeItem>onvif://www.onvif.org/name/YoLinkDashboard</tt:ScopeItem>
  </tds:Scopes>
</tds:GetScopesResponse>
"""
        return self._generate_soap_response(
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
        now = datetime.datetime.now()
        utc_now = datetime.datetime.utcnow()

        response = f"""
<tds:GetSystemDateAndTimeResponse>
  <tds:SystemDateAndTime>
    <tt:DateTimeType>NTP</tt:DateTimeType>
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
    <tt:LocalDateTime>
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
    </tt:LocalDateTime>
  </tds:SystemDateAndTime>
</tds:GetSystemDateAndTimeResponse>
"""
        return self._generate_soap_response(
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
        hostname = socket.gethostname()

        response = f"""
<tds:GetHostnameResponse>
  <tds:HostnameInformation>
    <tt:FromDHCP>false</tt:FromDHCP>
    <tt:Name>{hostname}</tt:Name>
  </tds:HostnameInformation>
</tds:GetHostnameResponse>
"""
        return self._generate_soap_response(
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
      <tt:HwAddress>00:11:22:33:44:55</tt:HwAddress>
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
        return self._generate_soap_response(
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
        return self._generate_soap_response(
            "http://www.onvif.org/ver10/device/wsdl/GetNetworkProtocolsResponse",
            response
        )

    def _generate_bye_message(self) -> str:
        """
        Generate a WS-Discovery Bye message to announce device going offline.

        Returns:
            str: XML Bye message
        """
        # Create SOAP envelope
        envelope = ET.Element('{http://www.w3.org/2003/05/soap-envelope}Envelope')

        # Add header
        header = ET.SubElement(envelope, '{http://www.w3.org/2003/05/soap-envelope}Header')
        action = ET.SubElement(header, '{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action')
        action.text = 'http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye'

        message_id = ET.SubElement(header, '{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID')
        message_id.text = f'urn:uuid:{uuid.uuid4()}'

        to = ET.SubElement(header, '{http://schemas.xmlsoap.org/ws/2004/08/addressing}To')
        to.text = 'urn:schemas-xmlsoap-org:ws:2005:04:discovery'

        # Add body
        body = ET.SubElement(envelope, '{http://www.w3.org/2003/05/soap-envelope}Body')
        bye = ET.SubElement(body, '{http://schemas.xmlsoap.org/ws/2005/04/discovery}Bye')

        endpoint_ref = ET.SubElement(bye, '{http://schemas.xmlsoap.org/ws/2004/08/addressing}EndpointReference')
        address = ET.SubElement(endpoint_ref, '{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address')
        address.text = f'urn:uuid:{self.device_uuid}'

        return ET.tostring(envelope, encoding='utf-8', method='xml').decode('utf-8')

    def _send_bye_announcement(self) -> None:
        """
        Send a WS-Discovery Bye announcement to notify that the device is going offline.
        """
        try:
            # Create a new socket if we don't have one or the existing one is closed
            if self.multicast_socket is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            else:
                sock = self.multicast_socket

            # Generate and send the Bye message
            bye_msg = self._generate_bye_message()
            sock.sendto(bye_msg.encode(), (self.multicast_address, self.multicast_port))
            logger.info("Sent WS-Discovery Bye announcement")

            # Close the socket if we created a new one
            if self.multicast_socket is None:
                sock.close()

        except Exception as e:
            logger.error(f"Failed to send Bye announcement: {e}")

    def stop(self) -> None:
        """
        Stop the ONVIF service. Sends a Bye message for proper cleanup.
        """
        logger.info("Stopping ONVIF service")

        # First mark as not running to stop main thread loops
        with self.lock:
            self.running = False

        # Send Bye message with multiple attempts for reliability
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                with self.lock:
                    self._send_bye_announcement()
                    logger.info(f"Successfully sent Bye announcement (attempt {attempt})")
                    break
            except Exception as e:
                logger.warning(f"Bye announcement attempt {attempt}/{max_attempts} failed: {e}")
                # Only wait if we have more attempts left
                if attempt < max_attempts:
                    time.sleep(0.5)

        # Close multicast socket if it exists - with timeout protection
        if hasattr(self, 'multicast_socket') and self.multicast_socket:
            try:
                with self.lock:
                    self.multicast_socket.close()
                    self.multicast_socket = None
                    logger.debug("Multicast socket closed")
            except Exception as e:
                logger.error(f"Error closing multicast socket: {e}")

        logger.info("ONVIF service stopped")

    def update_media_profiles(self, config: Dict[str, Any]) -> None:
        """
        Update the media profiles based on configuration changes.
        Creates appropriate profiles for different resolutions.
        Thread-safe method to refresh profile data.

        Args:
            config: New configuration dictionary
        """
        with self.lock:
            # Main high-resolution profile
            primary_width = config.get("width", 1920)
            primary_height = config.get("height", 1080)
            primary_fps = config.get("frame_rate", 6)
            primary_bitrate = config.get("bitrate", 4000)
            primary_quality = config.get("quality", 5)
            primary_gop = config.get("gop", 30)
            primary_profile = config.get("h264_profile", "High")

            # Clear existing profiles and add the main profile
            self.media_profiles = [
                {
                    "token": "profile1",
                    "name": config.get("profile_name", "YoLink Main Stream"),
                    "resolution": {"width": primary_width, "height": primary_height},
                    "fps": primary_fps,
                    "encoding": "H264",
                    "bitrate": primary_bitrate,
                    "quality": primary_quality,
                    "gop": primary_gop,
                    "profile": primary_profile,
                    "sensors_per_page": config.get("sensors_per_page", 20)
                }
            ]

            # Add low-resolution profile if enabled
            if config.get("enable_low_res_profile", False):
                # Get low-res specific config or calculate from main profile
                low_width = config.get("low_res_width", primary_width // 2)
                low_height = config.get("low_res_height", primary_height // 2)
                low_fps = config.get("low_res_fps", min(primary_fps, 4))  # Lower framerate for low-res
                low_bitrate = config.get("low_res_bitrate", primary_bitrate // 4)

                # Calculate appropriate sensors per page for low-res
                # For smaller resolutions, we want fewer sensors to maintain readability
                if primary_width >= 1920 and low_width <= 960:
                    # For half HD resolution or lower, reduce to 6 sensors
                    sensors_per_page = config.get("low_res_sensors_per_page", 6)
                else:
                    # For other resolutions, calculate proportionally (min 4, max 20)
                    ratio = (low_width * low_height) / (primary_width * primary_height)
                    sensors_per_page = max(4, min(20, int(20 * ratio)))

                self.media_profiles.append({
                    "token": "profile2",
                    "name": "Low Resolution Stream",
                    "resolution": {"width": low_width, "height": low_height},
                    "fps": low_fps,
                    "encoding": "H264",
                    "bitrate": low_bitrate,
                    "quality": primary_quality,
                    "gop": primary_gop,
                    "profile": "Baseline",  # Use Baseline for better compatibility
                    "sensors_per_page": sensors_per_page
                })

                logger.info(f"Added low-resolution profile: {low_width}x{low_height} @ {low_fps}fps, "
                            f"{sensors_per_page} sensors per page")

            # Add even lower resolution profile for mobile/remote access if enabled
            if config.get("enable_mobile_profile", False):
                mobile_width = config.get("mobile_width", primary_width // 4)
                mobile_height = config.get("mobile_height", primary_height // 4)
                mobile_fps = config.get("mobile_fps", 2)
                mobile_bitrate = config.get("mobile_bitrate", primary_bitrate // 10)

                # For very small resolutions, show only 4 sensors per page
                sensors_per_page = config.get("mobile_sensors_per_page", 4)

                self.media_profiles.append({
                    "token": "profile3",
                    "name": "Mobile Stream",
                    "resolution": {"width": mobile_width, "height": mobile_height},
                    "fps": mobile_fps,
                    "encoding": "H264",
                    "bitrate": mobile_bitrate,
                    "quality": primary_quality,
                    "gop": primary_gop,
                    "profile": "Baseline",
                    "sensors_per_page": sensors_per_page
                })

                logger.info(f"Added mobile profile: {mobile_width}x{mobile_height} @ {mobile_fps}fps, "
                            f"{sensors_per_page} sensors per page")

            logger.info(f"Media profiles updated: {len(self.media_profiles)} profiles configured")

            # Update RTSP streamer if available and supports multiple profiles
            # (This would require implementing multi-resolution support in the RTSP streamer)
            if hasattr(self, 'update_rtsp_profiles') and callable(self.update_rtsp_profiles):
                self.update_rtsp_profiles(self.media_profiles)

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get the device capabilities as a structured dictionary.

        Returns:
            Dict[str, Any]: Dictionary of device capabilities
        """
        server_ip = self.server_ip
        onvif_port = self.onvif_port

        # Base URLs for services
        device_url = f"http://{server_ip}:{onvif_port}/onvif/device_service"
        media_url = f"http://{server_ip}:{onvif_port}/onvif/media_service"

        # Build capabilities dictionary
        capabilities = {
            "device": {
                "xaddr": device_url,
                "network": {
                    "ip_filter": False,
                    "zero_configuration": False,
                    "ip_version6": False,
                    "dyn_dns": False
                },
                "system": {
                    "discovery_resolve": True,
                    "discovery_bye": True,
                    "remote_discovery": True,
                    "system_backup": False,
                    "system_logging": False,
                    "firmware_upgrade": False,
                    "supported_versions": {"major": 1, "minor": 0}
                },
                "security": {
                    "tls1.1": False,
                    "tls1.2": False,
                    "onboard_key_generation": False,
                    "access_policy_config": False,
                    "default_access_policy": False,
                    "dot1x": False,
                    "remote_user_handling": False,
                    "x509_token": False,
                    "saml_token": False,
                    "kerberos_token": False,
                    "username_token": True,  # We support username/password auth
                    "http_digest": False,
                    "rel_token": False
                },
                "extensions": {}
            },
            "media": {
                "xaddr": media_url,
                "streaming": {
                    "rtp_multicast": False,
                    "rtp_tcp": True,
                    "rtp_rtsp_tcp": True
                },
                "snapshot": True,  # We do support snapshots
                "rotation": False,
                "video_source_mode": False,
                "osd": False,
                "temporary_osd_text": False
            },
            "events": {
                "xaddr": f"http://{server_ip}:{onvif_port}/onvif/events_service",
                "ws_subscription_policy_support": False,
                "ws_pull_point_support": False,
                "ws_pausable_subscription_manager_interface_support": False
            },
            "analytics": None,  # We don't support analytics
            "device_io": None,  # We don't support deviceIO
            "imaging": None,    # We don't support imaging
            "ptz": None,        # We don't support PTZ (Pan/Tilt/Zoom)
            "recording": None,  # We don't support recording
            "search": None,     # We don't support search
            "replay": None,     # We don't support replay
            "receiver": None,   # We don't support receiver
            "extensions": {}
        }

        return capabilities

        if self.http_server:
            self.http_server.shutdown()