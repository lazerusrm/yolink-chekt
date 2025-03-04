"""
ONVIF API endpoints for the YoLink Dashboard RTSP Server.
"""
import io
import uuid
import logging
import base64
import datetime
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, List, Tuple

from flask import Flask, request, Response

logger = logging.getLogger(__name__)

# ONVIF XML namespaces
NAMESPACES = {
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
for prefix, uri in NAMESPACES.items():
    ET.register_namespace(prefix, uri)


    def create_onvif_routes(app: Flask, config: Dict[str, Any], onvif_service=None, renderer=None) -> None:
        """
    Configure ONVIF API routes for the YoLink Dashboard RTSP Server.

    Args:
        app: Flask application
        config: Application configuration
        onvif_service: Optional OnvifService instance for authentication
    """
    app.config['renderer'] = renderer
    @app.route('/onvif/device_service', methods=["POST"])
    def onvif_device_service():
        """
        Handle ONVIF device service requests.
        """
        # Get request XML
        soap_request = request.data.decode('utf-8')
        logger.debug(f"Received ONVIF device service request: {soap_request[:100]}...")

        # Check authentication if onvif_service is provided
        if onvif_service and onvif_service.authentication_required:
            if not onvif_service.check_authentication(request.headers, soap_request):
                logger.warning("Authentication failed for ONVIF device service request")
                return Response(
                    generate_fault_response(
                        "Authentication failed",
                        "ter:NotAuthorized"
                    ),
                    status=401,
                    mimetype="application/soap+xml"
                )

        try:
            # Parse the SOAP request
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NAMESPACES)

            if body is None:
                return Response(
                    generate_fault_response(
                        "Invalid SOAP request",
                        "ter:InvalidXML"
                    ),
                    mimetype="application/soap+xml"
                )

            # Extract the action from the request
            action_element = None
            for child in body:
                action_element = child
                break

            if action_element is None:
                return Response(
                    generate_fault_response(
                        "No action element found",
                        "ter:InvalidXML"
                    ),
                    mimetype="application/soap+xml"
                )

            # Get local name without namespace
            if '}' in action_element.tag:
                local_name = action_element.tag.split('}', 1)[1]
            else:
                local_name = action_element.tag

            # Log the operation being handled
            logger.info(f"Handling ONVIF device operation: {local_name}")

            # Handle different device service actions
            if local_name == 'GetDeviceInformation':
                response = handle_get_device_information(config, onvif_service)
            elif local_name == 'GetServices':
                response = handle_get_services(config, onvif_service, action_element)
            elif local_name == 'GetCapabilities':
                response = handle_get_capabilities(config, onvif_service)
            elif local_name == 'GetServiceCapabilities':
                response = handle_get_service_capabilities(config, 'device')
            elif local_name == 'GetScopes':
                response = handle_get_scopes(config, onvif_service)
            elif local_name == 'GetSystemDateAndTime':
                response = handle_get_system_date_and_time()
            elif local_name == 'GetHostname':
                response = handle_get_hostname()
            elif local_name == 'GetNetworkInterfaces':
                response = handle_get_network_interfaces(config)
            elif local_name == 'GetNetworkProtocols':
                response = handle_get_network_protocols(config)
            else:
                logger.warning(f"Unsupported device service action: {local_name}")
                return Response(
                    generate_fault_response(
                        f"Unsupported action: {local_name}",
                        "ter:ActionNotSupported"
                    ),
                    mimetype="application/soap+xml"
                )

            logger.debug(f"Sending ONVIF device response for {local_name}")
            return Response(response, mimetype="application/soap+xml")

        except Exception as e:
            logger.error(f"Error handling device service request: {e}")
            return Response(
                generate_fault_response(
                    f"Internal error: {str(e)}",
                    "ter:InternalError"
                ),
                mimetype="application/soap+xml"
            )

    @app.route('/onvif/media_service', methods=["POST"])
    def onvif_media_service():
        """
        Handle ONVIF media service requests.
        """
        # Get request XML
        soap_request = request.data.decode('utf-8')
        logger.debug(f"Received ONVIF media service request: {soap_request[:100]}...")

        # Check authentication if onvif_service is provided
        if onvif_service and onvif_service.authentication_required:
            if not onvif_service.check_authentication(request.headers, soap_request):
                logger.warning("Authentication failed for ONVIF media service request")
                return Response(
                    generate_fault_response("Authentication failed"),
                    status=401,
                    mimetype="application/soap+xml"
                )

        try:
            # Parse the SOAP request
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NAMESPACES)

            if body is None:
                return Response(
                    generate_fault_response("Invalid SOAP request"),
                    mimetype="application/soap+xml"
                )

            # Extract the action from the request
            action_element = None
            for child in body:
                action_element = child
                break

            if action_element is None:
                return Response(
                    generate_fault_response("No action element found"),
                    mimetype="application/soap+xml"
                )

            # Get local name without namespace
            if '}' in action_element.tag:
                local_name = action_element.tag.split('}', 1)[1]
            else:
                local_name = action_element.tag

            # Handle different media service actions
            if local_name == 'GetProfiles':
                response = handle_get_profiles(config, onvif_service)
            elif local_name == 'GetProfile':
                profile_token = action_element.find('.//trt:ProfileToken', NAMESPACES)
                token = profile_token.text if profile_token is not None else "profile1"
                response = handle_get_profile(config, onvif_service, token)
            elif local_name == 'GetStreamUri':
                profile_token = action_element.find('.//trt:ProfileToken', NAMESPACES)
                token = profile_token.text if profile_token is not None else "profile1"
                response = handle_get_stream_uri(config, onvif_service, token)
            elif local_name == 'GetSnapshotUri':
                profile_token = action_element.find('.//trt:ProfileToken', NAMESPACES)
                token = profile_token.text if profile_token is not None else "profile1"
                response = handle_get_snapshot_uri(config, token)
            elif local_name == 'GetVideoEncoderConfigurations':
                response = handle_get_video_encoder_configurations(config, onvif_service)
            elif local_name == 'GetServiceCapabilities':
                response = handle_get_service_capabilities(config, 'media')
            else:
                logger.warning(f"Unsupported media service action: {local_name}")
                return Response(
                    generate_fault_response(f"Unsupported action: {local_name}"),
                    mimetype="application/soap+xml"
                )

            return Response(response, mimetype="application/soap+xml")

        except Exception as e:
            logger.error(f"Error handling media service request: {e}")
            return Response(
                generate_fault_response(f"Internal error: {str(e)}"),
                mimetype="application/soap+xml"
            )

    # Add route for snapshot image if needed
    @app.route('/onvif/snapshot', methods=["GET"])
    def onvif_snapshot():
        """
        Handle ONVIF snapshot image requests.
        Provides a real-time snapshot of the current dashboard view with authentication.
        """
        # Check authentication if needed
        renderer = app.config['renderer']
        if config.get("onvif_auth_required", True) and onvif_service:
            auth_header = request.headers.get('Authorization')

            if not auth_header:
                # Check URL-based auth (username:password@server format)
                auth = request.authorization
                if auth and auth.username == onvif_service.username and auth.password == onvif_service.password:
                    logger.debug("Snapshot authenticated via URL parameters")
                else:
                    # Try HTTP Basic auth
                    if not onvif_service.check_authentication(request.headers):
                        logger.warning("Authentication failed for snapshot request")
                        response = Response("Authentication required", 401)
                        response.headers['WWW-Authenticate'] = 'Basic realm="ONVIF"'
                        return response

        # Ensure we have a renderer
        if renderer is None:
            logger.error("Renderer not provided to onvif_routes - cannot generate snapshot")
            return Response("Internal server error - renderer not available", 500)

        try:
            # Generate a fresh snapshot from the renderer
            logger.debug("Generating snapshot image")

            # Get the current frame from renderer
            frame = renderer.render_frame(
                config.get('width', 1920),
                config.get('height', 1080)
            )

            # Convert to JPEG
            buf = io.BytesIO()
            frame.save(buf, format="JPEG", quality=90)
            buf.seek(0)

            # Return as HTTP response with proper MIME type
            response = Response(buf.getvalue(), mimetype="image/jpeg")
            response.headers['Content-Disposition'] = 'inline; filename="snapshot.jpg"'
            return response

        except Exception as e:
            logger.error(f"Error generating snapshot: {e}")
            return Response("Failed to generate snapshot", 500)


def generate_soap_response(action: str, body_content: str, msg_id: str = None) -> str:
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


def generate_fault_response(reason: str, subcode: str = None) -> str:
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


def handle_get_device_information(config: Dict[str, Any], onvif_service=None) -> str:
    """
    Handle GetDeviceInformation request.

    Args:
        config: Application configuration
        onvif_service: Optional OnvifService instance for device info

    Returns:
        str: SOAP response XML
    """
    # Use device info from onvif_service if available, otherwise use defaults
    if onvif_service:
        device_info = onvif_service.device_info
    else:
        device_info = {
            "Manufacturer": "YoLink",
            "Model": "Dashboard-RTSP",
            "FirmwareVersion": "1.0.0",
            "SerialNumber": str(uuid.uuid4()),
            "HardwareId": "YOLINK-DASHBOARD-1"
        }

    response = f"""
<tds:GetDeviceInformationResponse>
  <tds:Manufacturer>{device_info['Manufacturer']}</tds:Manufacturer>
  <tds:Model>{device_info['Model']}</tds:Model>
  <tds:FirmwareVersion>{device_info['FirmwareVersion']}</tds:FirmwareVersion>
  <tds:SerialNumber>{device_info['SerialNumber']}</tds:SerialNumber>
  <tds:HardwareId>{device_info['HardwareId']}</tds:HardwareId>
</tds:GetDeviceInformationResponse>
"""
    return generate_soap_response(
        "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse",
        response
    )


def handle_get_services(config: Dict[str, Any], onvif_service, request_elem) -> str:
    """
    Handle GetServices request.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance
        request_elem: Request XML element

    Returns:
        str: SOAP response XML
    """
    include_capability = True
    include_capability_elem = request_elem.find('.//tds:IncludeCapability', NAMESPACES)
    if include_capability_elem is not None:
        include_capability = include_capability_elem.text.lower() == 'true'

    # Base URLs
    server_ip = config.get("server_ip")
    onvif_port = config.get("onvif_port", 8555)
    device_service_url = f"http://{server_ip}:{onvif_port}/onvif/device_service"
    media_service_url = f"http://{server_ip}:{onvif_port}/onvif/media_service"

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
    <tds:XAddr>{device_service_url}</tds:XAddr>
    <tds:Version>
      <tt:Major>1</tt:Major>
      <tt:Minor>0</tt:Minor>
    </tds:Version>
    {capability_device}
  </tds:Service>
  <tds:Service>
    <tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>
    <tds:XAddr>{media_service_url}</tds:XAddr>
    <tds:Version>
      <tt:Major>1</tt:Major>
      <tt:Minor>0</tt:Minor>
    </tds:Version>
    {capability_media}
  </tds:Service>
</tds:GetServicesResponse>
"""
    return generate_soap_response(
        "http://www.onvif.org/ver10/device/wsdl/GetServicesResponse",
        response
    )


def handle_get_capabilities(config: Dict[str, Any], onvif_service) -> str:
    """
    Handle GetCapabilities request.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance

    Returns:
        str: SOAP response XML
    """
    # Use capabilities from onvif_service if available
    if onvif_service and hasattr(onvif_service, 'get_capabilities'):
        try:
            capabilities = onvif_service.get_capabilities()

            # Build response using the capabilities dictionary
            device_xaddr = capabilities["device"]["xaddr"]
            media_xaddr = capabilities["media"]["xaddr"]

            response = f"""
<tds:GetCapabilitiesResponse>
  <tds:Capabilities>
    <tt:Device>
      <tt:XAddr>{device_xaddr}</tt:XAddr>
      <tt:Network>
        <tt:IPFilter>{str(capabilities["device"]["network"]["ip_filter"]).lower()}</tt:IPFilter>
        <tt:ZeroConfiguration>{str(capabilities["device"]["network"]["zero_configuration"]).lower()}</tt:ZeroConfiguration>
        <tt:IPVersion6>{str(capabilities["device"]["network"]["ip_version6"]).lower()}</tt:IPVersion6>
        <tt:DynDNS>{str(capabilities["device"]["network"]["dyn_dns"]).lower()}</tt:DynDNS>
      </tt:Network>
      <tt:System>
        <tt:DiscoveryResolve>{str(capabilities["device"]["system"]["discovery_resolve"]).lower()}</tt:DiscoveryResolve>
        <tt:DiscoveryBye>{str(capabilities["device"]["system"]["discovery_bye"]).lower()}</tt:DiscoveryBye>
        <tt:RemoteDiscovery>{str(capabilities["device"]["system"]["remote_discovery"]).lower()}</tt:RemoteDiscovery>
        <tt:SystemBackup>{str(capabilities["device"]["system"]["system_backup"]).lower()}</tt:SystemBackup>
        <tt:SystemLogging>{str(capabilities["device"]["system"]["system_logging"]).lower()}</tt:SystemLogging>
        <tt:FirmwareUpgrade>{str(capabilities["device"]["system"]["firmware_upgrade"]).lower()}</tt:FirmwareUpgrade>
        <tt:SupportedVersions>
          <tt:Major>{capabilities["device"]["system"]["supported_versions"]["major"]}</tt:Major>
          <tt:Minor>{capabilities["device"]["system"]["supported_versions"]["minor"]}</tt:Minor>
        </tt:SupportedVersions>
      </tt:System>
      <tt:Security>
        <tt:TLS1.1>{str(capabilities["device"]["security"]["tls1.1"]).lower()}</tt:TLS1.1>
        <tt:TLS1.2>{str(capabilities["device"]["security"]["tls1.2"]).lower()}</tt:TLS1.2>
        <tt:OnboardKeyGeneration>{str(capabilities["device"]["security"]["onboard_key_generation"]).lower()}</tt:OnboardKeyGeneration>
        <tt:AccessPolicyConfig>{str(capabilities["device"]["security"]["access_policy_config"]).lower()}</tt:AccessPolicyConfig>
        <tt:DefaultAccessPolicy>{str(capabilities["device"]["security"]["default_access_policy"]).lower()}</tt:DefaultAccessPolicy>
        <tt:Dot1X>{str(capabilities["device"]["security"]["dot1x"]).lower()}</tt:Dot1X>
        <tt:RemoteUserHandling>{str(capabilities["device"]["security"]["remote_user_handling"]).lower()}</tt:RemoteUserHandling>
        <tt:X.509Token>{str(capabilities["device"]["security"]["x509_token"]).lower()}</tt:X.509Token>
        <tt:SAMLToken>{str(capabilities["device"]["security"]["saml_token"]).lower()}</tt:SAMLToken>
        <tt:KerberosToken>{str(capabilities["device"]["security"]["kerberos_token"]).lower()}</tt:KerberosToken>
        <tt:UsernameToken>{str(capabilities["device"]["security"]["username_token"]).lower()}</tt:UsernameToken>
        <tt:HttpDigest>{str(capabilities["device"]["security"]["http_digest"]).lower()}</tt:HttpDigest>
        <tt:RELToken>{str(capabilities["device"]["security"]["rel_token"]).lower()}</tt:RELToken>
      </tt:Security>
    </tt:Device>
    <tt:Media>
      <tt:XAddr>{media_xaddr}</tt:XAddr>
      <tt:StreamingCapabilities>
        <tt:RTPMulticast>{str(capabilities["media"]["streaming"]["rtp_multicast"]).lower()}</tt:RTPMulticast>
        <tt:RTP_TCP>{str(capabilities["media"]["streaming"]["rtp_tcp"]).lower()}</tt:RTP_TCP>
        <tt:RTP_RTSP_TCP>{str(capabilities["media"]["streaming"]["rtp_rtsp_tcp"]).lower()}</tt:RTP_RTSP_TCP>
      </tt:StreamingCapabilities>
      <tt:SnapshotUri>{str(capabilities["media"]["snapshot"]).lower()}</tt:SnapshotUri>
      <tt:Rotation>{str(capabilities["media"]["rotation"]).lower()}</tt:Rotation>
    </tt:Media>
  </tds:Capabilities>
</tds:GetCapabilitiesResponse>
"""
            return generate_soap_response(
                "http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse",
                response
            )

        except Exception as e:
            logger.error(f"Error using onvif_service.get_capabilities(): {e}")
            # Continue with the default implementation below

    # Default implementation if onvif_service is not available or has no get_capabilities method
    server_ip = config.get("server_ip")
    onvif_port = config.get("onvif_port", 8555)
    device_service_url = f"http://{server_ip}:{onvif_port}/onvif/device_service"
    media_service_url = f"http://{server_ip}:{onvif_port}/onvif/media_service"

    response = f"""
<tds:GetCapabilitiesResponse>
  <tds:Capabilities>
    <tt:Device>
      <tt:XAddr>{device_service_url}</tt:XAddr>
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
      <tt:XAddr>{media_service_url}</tt:XAddr>
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
    return generate_soap_response(
        "http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse",
        response
    )


def handle_get_service_capabilities(config: Dict[str, Any], service_type: str) -> str:
    """
    Handle GetServiceCapabilities request for different services.

    Args:
        config: Application configuration
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
        return generate_fault_response(f"Unknown service type: {service_type}")

    return generate_soap_response(action, response)


def handle_get_profiles(config: Dict[str, Any], onvif_service) -> str:
    """
    Handle GetProfiles request.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance

    Returns:
        str: SOAP response XML
    """
    # Use media profiles from onvif_service if available, otherwise use defaults
    if onvif_service and hasattr(onvif_service, 'media_profiles'):
        profiles = onvif_service.media_profiles
    else:
        profiles = [
            {
                "token": "profile1",
                "name": "YoLink Main Stream",
                "resolution": {"width": config.get("width", 1920), "height": config.get("height", 1080)},
                "fps": config.get("frame_rate", 6),
                "encoding": "H264"
            }
        ]

    profiles_xml = ""
    for profile in profiles:
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
    return generate_soap_response(
        "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse",
        response
    )


def handle_get_profile(config: Dict[str, Any], onvif_service, token: str) -> str:
    """
    Handle GetProfile request.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance
        token: Profile token

    Returns:
        str: SOAP response XML
    """
    # Use media profiles from onvif_service if available, otherwise use defaults
    if onvif_service and hasattr(onvif_service, 'media_profiles'):
        profiles = onvif_service.media_profiles
    else:
        profiles = [
            {
                "token": "profile1",
                "name": "YoLink Main Stream",
                "resolution": {"width": config.get("width", 1920), "height": config.get("height", 1080)},
                "fps": config.get("frame_rate", 6),
                "encoding": "H264"
            }
        ]

    # Find the requested profile
    profile = None
    for p in profiles:
        if p['token'] == token:
            profile = p
            break

    if profile is None:
        # If token not found, use the first profile
        profile = profiles[0]

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
    return generate_soap_response(
        "http://www.onvif.org/ver10/media/wsdl/GetProfileResponse",
        response
    )


def handle_get_stream_uri(config: Dict[str, Any], onvif_service, token: str) -> str:
    """
    Handle GetStreamUri request.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance
        token: Profile token

    Returns:
        str: SOAP response XML
    """
    server_ip = config.get("server_ip")
    rtsp_port = config.get("rtsp_port", 8554)
    stream_name = config.get("stream_name", "yolink-dashboard")

    # Get auth parameters for RTSP URL if needed
    auth_part = ""
    if onvif_service and onvif_service.authentication_required:
        auth_part = f"{onvif_service.username}:{onvif_service.password}@"

    # Return RTSP URI
    stream_url = f"rtsp://{auth_part}{server_ip}:{rtsp_port}/{stream_name}"

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
    return generate_soap_response(
        "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
        response
    )


def handle_get_snapshot_uri(config: Dict[str, Any], token: str) -> str:
    """
    Handle GetSnapshotUri request with authentication support.

    Args:
        config: Application configuration
        token: Profile token

    Returns:
        str: SOAP response XML
    """
    server_ip = config.get("server_ip")
    http_port = config.get("http_port", 3001)

    # Add authentication parameters to snapshot URL if auth is required
    auth_part = ""
    if config.get("onvif_auth_required", True):
        username = config.get("onvif_username", "admin")
        password = config.get("onvif_password", "123456")
        auth_part = f"{username}:{password}@"

    # Return HTTP URI for snapshot with proper auth if needed
    snapshot_url = f"http://{auth_part}{server_ip}:{http_port}/onvif/snapshot"

    logger.info(
        f"Providing snapshot URI for profile {token}: {snapshot_url.replace(auth_part, '***:***@' if auth_part else '')}")

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
    return generate_soap_response(
        "http://www.onvif.org/ver10/media/wsdl/GetSnapshotUriResponse",
        response
    )


def handle_get_video_encoder_configurations(config: Dict[str, Any], onvif_service) -> str:
    """
    Handle GetVideoEncoderConfigurations request.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance

    Returns:
        str: SOAP response XML
    """
    # Use media profiles from onvif_service if available, otherwise use defaults
    if onvif_service and hasattr(onvif_service, 'media_profiles'):
        profiles = onvif_service.media_profiles
    else:
        profiles = [
            {
                "token": "profile1",
                "name": "YoLink Main Stream",
                "resolution": {"width": config.get("width", 1920), "height": config.get("height", 1080)},
                "fps": config.get("frame_rate", 6),
                "encoding": "H264"
            }
        ]

    video_encoders = ""
    for profile in profiles:
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
    return generate_soap_response(
        "http://www.onvif.org/ver10/media/wsdl/GetVideoEncoderConfigurationsResponse",
        response
    )


def handle_get_scopes(config: Dict[str, Any], onvif_service) -> str:
    """
    Handle GetScopes request.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance

    Returns:
        str: SOAP response XML
    """
    model = "YoLink-Dashboard"
    if onvif_service and hasattr(onvif_service, 'device_info'):
        model = onvif_service.device_info.get("Model", "YoLink-Dashboard")

    response = f"""
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
    <tt:ScopeItem>onvif://www.onvif.org/hardware/{model}</tt:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tt:ScopeDef>Fixed</tt:ScopeDef>
    <tt:ScopeItem>onvif://www.onvif.org/location/Dashboard</tt:ScopeItem>
  </tds:Scopes>
  <tds:Scopes>
    <tt:ScopeDef>Fixed</tt:ScopeDef>
    <tt:ScopeItem>onvif://www.onvif.org/name/{model}</tt:ScopeItem>
  </tds:Scopes>
</tds:GetScopesResponse>
"""
    return generate_soap_response(
        "http://www.onvif.org/ver10/device/wsdl/GetScopesResponse",
        response
    )


def handle_get_system_date_and_time() -> str:
    """
    Handle GetSystemDateAndTime request.

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
    return generate_soap_response(
        "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse",
        response
    )


def handle_get_hostname() -> str:
    """
    Handle GetHostname request.

    Returns:
        str: SOAP response XML
    """
    import socket
    hostname = socket.gethostname()

    response = f"""
<tds:GetHostnameResponse>
  <tds:HostnameInformation>
    <tt:FromDHCP>false</tt:FromDHCP>
    <tt:Name>{hostname}</tt:Name>
  </tds:HostnameInformation>
</tds:GetHostnameResponse>
"""
    return generate_soap_response(
        "http://www.onvif.org/ver10/device/wsdl/GetHostnameResponse",
        response
    )


def handle_get_network_interfaces(config: Dict[str, Any]) -> str:
    """
    Handle GetNetworkInterfaces request.

    Args:
        config: Application configuration

    Returns:
        str: SOAP response XML
    """
    server_ip = config.get("server_ip")

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
          <tt:Address>{server_ip}</tt:Address>
          <tt:PrefixLength>24</tt:PrefixLength>
        </tt:Manual>
        <tt:DHCP>false</tt:DHCP>
      </tt:Config>
    </tt:IPv4>
  </tds:NetworkInterfaces>
</tds:GetNetworkInterfacesResponse>
"""
    return generate_soap_response(
        "http://www.onvif.org/ver10/device/wsdl/GetNetworkInterfacesResponse",
        response
    )


def handle_get_network_protocols(config: Dict[str, Any]) -> str:
    """
    Handle GetNetworkProtocols request.

    Args:
        config: Application configuration

    Returns:
        str: SOAP response XML
    """
    onvif_port = config.get("onvif_port", 8555)
    rtsp_port = config.get("rtsp_port", 8554)
    http_port = config.get("http_port", 3001)

    response = f"""
<tds:GetNetworkProtocolsResponse>
  <tds:NetworkProtocols>
    <tt:Name>HTTP</tt:Name>
    <tt:Enabled>true</tt:Enabled>
    <tt:Port>{http_port}</tt:Port>
  </tds:NetworkProtocols>
  <tds:NetworkProtocols>
    <tt:Name>RTSP</tt:Name>
    <tt:Enabled>true</tt:Enabled>
    <tt:Port>{rtsp_port}</tt:Port>
  </tds:NetworkProtocols>
</tds:GetNetworkProtocolsResponse>
"""
    return generate_soap_response(
        "http://www.onvif.org/ver10/device/wsdl/GetNetworkProtocolsResponse",
        response
    )