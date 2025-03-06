"""
ONVIF API endpoints for the YoLink Dashboard RTSP Server.
Provides Profile S compatible HTTP endpoints that delegate to the OnvifService when available.
"""
import io
import uuid
import logging
import datetime
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, List, Tuple, Union
from config import MAC_ADDRESS

from flask import Flask, request, Response, abort, make_response, jsonify

logger = logging.getLogger(__name__)

# ONVIF XML namespaces
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
    'ter': 'http://www.onvif.org/ver10/error',
    'tns1': 'http://www.onvif.org/ver10/topics'
}

# Register namespace prefixes for pretty XML output
for prefix, uri in NAMESPACES.items():
    ET.register_namespace(prefix, uri)


def create_onvif_routes(app: Flask, config: Dict[str, Any], onvif_service=None, renderer=None) -> None:
    """
    Configure ONVIF API routes for the YoLink Dashboard RTSP Server.
    Uses OnvifService when available, or provides standalone implementations.

    Args:
        app: Flask application
        config: Application configuration
        onvif_service: Optional OnvifService instance (preferred for delegation)
        renderer: DashboardRenderer instance to get frames from
    """
    # Store services in app context for use in routes
    if renderer is not None:
        app.config['renderer'] = renderer
    if onvif_service is not None:
        app.config['onvif_service'] = onvif_service

    @app.route('/onvif/device_service', methods=["POST"])
    def onvif_device_service():
        """
        Handle ONVIF device service requests.
        Delegates to OnvifService when available, otherwise handles locally.
        """
        soap_request = request.data.decode('utf-8')
        logger.debug(f"Received ONVIF device service request: {soap_request[:100]}...")

        # Get OnvifService instance if available
        onvif_service = app.config.get('onvif_service')

        # If OnvifService is available, delegate the request
        if onvif_service and hasattr(onvif_service, 'handle_device_service'):
            # Check authentication first
            if onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Delegate to OnvifService
            try:
                soap_response = onvif_service.handle_device_service(soap_request)
                return Response(soap_response, mimetype="application/soap+xml")
            except Exception as e:
                logger.error(f"Error delegating to OnvifService: {e}", exc_info=True)
                return Response(
                    generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                    mimetype="application/soap+xml"
                )

        # If OnvifService is not available or delegation fails, handle locally
        try:
            # Check authentication
            if onvif_service and onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

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

            # Extract the action
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
            elif local_name == 'GetDiscoveryMode':
                response = handle_get_discovery_mode()
            elif local_name == 'GetDNS':
                response = handle_get_dns()
            elif local_name == 'GetDynamicDNS':
                response = handle_get_dynamic_dns()
            elif local_name == 'GetUsers':
                response = handle_get_users(onvif_service)
            elif local_name == 'GetWsdlUrl':
                response = handle_get_wsdl_url()
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
            logger.error(f"Error handling device service request: {e}", exc_info=True)
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
        Delegates to OnvifService when available, otherwise handles locally.
        """
        soap_request = request.data.decode('utf-8')
        logger.debug(f"Received ONVIF media service request: {soap_request[:100]}...")

        # Get OnvifService instance if available
        onvif_service = app.config.get('onvif_service')

        # If OnvifService is available, delegate the request
        if onvif_service and hasattr(onvif_service, 'handle_media_service'):
            # Check authentication first
            if onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Delegate to OnvifService
            try:
                soap_response = onvif_service.handle_media_service(soap_request)
                return Response(soap_response, mimetype="application/soap+xml")
            except Exception as e:
                logger.error(f"Error delegating to OnvifService: {e}", exc_info=True)
                return Response(
                    generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                    mimetype="application/soap+xml"
                )

        # If OnvifService is not available or delegation fails, handle locally
        try:
            # Check authentication
            if onvif_service and onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Parse the SOAP request
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NAMESPACES)

            if body is None:
                return Response(
                    generate_fault_response("Invalid SOAP request", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Extract the action from the request
            action_element = None
            for child in body:
                action_element = child
                break

            if action_element is None:
                return Response(
                    generate_fault_response("No action element found", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Get local name without namespace
            if '}' in action_element.tag:
                local_name = action_element.tag.split('}', 1)[1]
            else:
                local_name = action_element.tag

            logger.info(f"Handling ONVIF media operation: {local_name}")

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
            elif local_name == 'GetVideoSourceConfigurations':
                response = handle_get_video_source_configurations(config, onvif_service)
            elif local_name == 'GetVideoSources':
                response = handle_get_video_sources(config, onvif_service)
            elif local_name == 'GetServiceCapabilities':
                response = handle_get_service_capabilities(config, 'media')
            elif local_name == 'GetVideoSourceConfigurationOptions':
                response = handle_get_video_source_configuration_options(config, onvif_service)
            elif local_name == 'GetVideoEncoderConfigurationOptions':
                response = handle_get_video_encoder_configuration_options(config, onvif_service)
            else:
                logger.warning(f"Unsupported media service action: {local_name}")
                return Response(
                    generate_fault_response(f"Unsupported action: {local_name}", "ter:ActionNotSupported"),
                    mimetype="application/soap+xml"
                )

            return Response(response, mimetype="application/soap+xml")

        except Exception as e:
            logger.error(f"Error handling media service request: {e}", exc_info=True)
            return Response(
                generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                mimetype="application/soap+xml"
            )

    @app.route('/onvif/events_service', methods=["POST"])
    def onvif_events_service():
        """
        Handle ONVIF events service requests.
        Delegates to OnvifService when available, otherwise handles locally.
        """
        soap_request = request.data.decode('utf-8')
        logger.debug(f"Received ONVIF events service request: {soap_request[:100]}...")

        # Get OnvifService instance if available
        onvif_service = app.config.get('onvif_service')

        # If OnvifService is available, delegate the request
        if onvif_service and hasattr(onvif_service, 'handle_events_service'):
            # Check authentication first
            if onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Delegate to OnvifService
            try:
                soap_response = onvif_service.handle_events_service(soap_request)
                return Response(soap_response, mimetype="application/soap+xml")
            except Exception as e:
                logger.error(f"Error delegating to OnvifService: {e}", exc_info=True)
                return Response(
                    generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                    mimetype="application/soap+xml"
                )

        # If OnvifService is not available or delegation fails, handle locally
        try:
            # Check authentication
            if onvif_service and onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Parse request
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NAMESPACES)

            if body is None:
                return Response(
                    generate_fault_response("Invalid SOAP request", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Extract action
            action_element = None
            for child in body:
                action_element = child
                break

            if action_element is None:
                return Response(
                    generate_fault_response("No action element found", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Get local name
            if '}' in action_element.tag:
                local_name = action_element.tag.split('}', 1)[1]
            else:
                local_name = action_element.tag

            # Log the operation being handled
            logger.info(f"Handling ONVIF events operation: {local_name}")

            # Handle actions
            if local_name == 'GetEventProperties':
                response = handle_get_event_properties()
            elif local_name == 'CreatePullPointSubscription':
                response = handle_create_pull_point_subscription(action_element)
            elif local_name == 'PullMessages':
                response = handle_pull_messages(action_element)
            elif local_name == 'Unsubscribe':
                response = handle_unsubscribe(action_element)
            elif local_name == 'Renew':
                response = handle_renew(action_element)
            elif local_name == 'SetSynchronizationPoint':
                response = handle_set_synchronization_point(action_element)
            elif local_name == 'GetServiceCapabilities':
                response = handle_get_service_capabilities(config, 'events')
            else:
                logger.warning(f"Unsupported events service action: {local_name}")
                return Response(
                    generate_fault_response(f"Unsupported action: {local_name}", "ter:ActionNotSupported"),
                    mimetype="application/soap+xml"
                )

            return Response(response, mimetype="application/soap+xml")

        except Exception as e:
            logger.error(f"Error handling events service request: {e}", exc_info=True)
            return Response(
                generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                mimetype="application/soap+xml"
            )

    @app.route('/onvif/ptz_service', methods=["POST"])
    def onvif_ptz_service():
        """
        Handle ONVIF PTZ service requests.
        Minimal implementation since we don't need full PTZ support.
        Delegates to OnvifService when available, otherwise handles locally.
        """
        soap_request = request.data.decode('utf-8')
        logger.debug(f"Received ONVIF PTZ service request: {soap_request[:100]}...")

        # Get OnvifService instance if available
        onvif_service = app.config.get('onvif_service')

        # If OnvifService is available, delegate the request
        if onvif_service and hasattr(onvif_service, 'handle_ptz_service'):
            # Check authentication first
            if onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Delegate to OnvifService
            try:
                soap_response = onvif_service.handle_ptz_service(soap_request)
                return Response(soap_response, mimetype="application/soap+xml")
            except Exception as e:
                logger.error(f"Error delegating to OnvifService: {e}", exc_info=True)
                return Response(
                    generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                    mimetype="application/soap+xml"
                )

        # If OnvifService is not available or delegation fails, handle locally with minimum functionality
        try:
            # Check authentication
            if onvif_service and onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Parse request
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NAMESPACES)

            if body is None:
                return Response(
                    generate_fault_response("Invalid SOAP request", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Extract action
            action_element = None
            for child in body:
                action_element = child
                break

            if action_element is None:
                return Response(
                    generate_fault_response("No action element found", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Get local name
            if '}' in action_element.tag:
                local_name = action_element.tag.split('}', 1)[1]
            else:
                local_name = action_element.tag

            # Log the operation being handled
            logger.info(f"Handling ONVIF PTZ operation: {local_name}")

            # Handle PTZ actions (minimal implementation)
            if local_name == 'GetConfigurations':
                response = handle_get_ptz_configurations()
            elif local_name == 'GetConfiguration':
                response = handle_get_ptz_configuration(action_element)
            elif local_name == 'GetStatus':
                response = handle_get_ptz_status(action_element)
            elif local_name == 'GetServiceCapabilities':
                response = handle_get_service_capabilities(config, 'ptz')
            else:
                # Return a standard error for unsupported PTZ operations
                logger.warning(f"Unsupported PTZ service action: {local_name}")
                return Response(
                    generate_fault_response(
                        f"Operation {local_name} not supported on this device",
                        "ter:ActionNotSupported"
                    ),
                    mimetype="application/soap+xml"
                )

            return Response(response, mimetype="application/soap+xml")

        except Exception as e:
            logger.error(f"Error handling PTZ service request: {e}", exc_info=True)
            return Response(
                generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                mimetype="application/soap+xml"
            )

    @app.route('/onvif/imaging_service', methods=["POST"])
    def onvif_imaging_service():
        """
        Handle ONVIF imaging service requests.
        Minimal implementation since it's not core to Profile S.
        Delegates to OnvifService when available, otherwise handles locally.
        """
        soap_request = request.data.decode('utf-8')
        logger.debug(f"Received ONVIF imaging service request: {soap_request[:100]}...")

        # Get OnvifService instance if available
        onvif_service = app.config.get('onvif_service')

        # If OnvifService is available, delegate the request
        if onvif_service and hasattr(onvif_service, 'handle_imaging_service'):
            # Check authentication first
            if onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Delegate to OnvifService
            try:
                soap_response = onvif_service.handle_imaging_service(soap_request)
                return Response(soap_response, mimetype="application/soap+xml")
            except Exception as e:
                logger.error(f"Error delegating to OnvifService: {e}", exc_info=True)
                return Response(
                    generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                    mimetype="application/soap+xml"
                )

        # If OnvifService is not available, return minimal implementation
        try:
            # Check authentication
            if onvif_service and onvif_service.authentication_required:
                if not check_authentication(onvif_service, request.headers, soap_request):
                    return Response(
                        generate_fault_response("Authentication failed", "ter:NotAuthorized"),
                        status=401,
                        mimetype="application/soap+xml"
                    )

            # Parse the request
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NAMESPACES)

            if body is None:
                return Response(
                    generate_fault_response("Invalid SOAP request", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Extract action element
            action_element = None
            for child in body:
                action_element = child
                break

            if action_element is None:
                return Response(
                    generate_fault_response("No action element found", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Get local name
            if '}' in action_element.tag:
                local_name = action_element.tag.split('}', 1)[1]
            else:
                local_name = action_element.tag

            logger.info(f"Handling ONVIF imaging operation: {local_name}")

            # Handle only GetServiceCapabilities for minimal compliance
            if local_name == 'GetServiceCapabilities':
                response = handle_get_service_capabilities(config, 'imaging')
            else:
                logger.warning(f"Unsupported imaging service action: {local_name}")
                return Response(
                    generate_fault_response(
                        f"Operation {local_name} not supported on this device",
                        "ter:ActionNotSupported"
                    ),
                    mimetype="application/soap+xml"
                )

            return Response(response, mimetype="application/soap+xml")

        except Exception as e:
            logger.error(f"Error handling imaging service request: {e}", exc_info=True)
            return Response(
                generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                mimetype="application/soap+xml"
            )

    @app.route('/onvif/snapshot', methods=["GET"])
    def onvif_snapshot():
        """
        Handle ONVIF snapshot image requests.
        Provides a real-time snapshot of the current dashboard view with authentication.
        """
        renderer = app.config.get('renderer')
        onvif_service = app.config.get('onvif_service')

        # Check authentication if needed
        if config.get("onvif_auth_required", True) and onvif_service:
            # Get authentication credentials
            auth = request.authorization
            authenticated = False

            # Check HTTP Basic auth
            if auth and auth.username == onvif_service.username and auth.password == onvif_service.password:
                authenticated = True
                logger.debug("Snapshot authenticated via HTTP Basic Auth")
            else:
                # Check URL-based auth (username:password@server format)
                auth_header = request.headers.get('Authorization')
                if auth_header:
                    if onvif_service.check_authentication(request.headers):
                        authenticated = True
                        logger.debug("Snapshot authenticated via headers")

                if not authenticated:
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
            logger.error(f"Error generating snapshot: {e}", exc_info=True)
            return Response("Failed to generate snapshot", 500)

    # Add route for WS-Discovery
    @app.route('/onvif/discovery', methods=["POST"])
    def onvif_discovery():
        """
        Handle WS-Discovery messages over HTTP.
        Provides a way for clients to discover the ONVIF service via HTTP.
        """
        soap_request = request.data.decode('utf-8')
        logger.debug(f"Received WS-Discovery message over HTTP: {soap_request[:100]}...")

        # Get OnvifService instance if available
        onvif_service = app.config.get('onvif_service')

        try:
            # Parse the request
            root = ET.fromstring(soap_request)
            body = root.find('.//soap:Body', NAMESPACES)

            if body is None:
                return Response(
                    generate_fault_response("Invalid SOAP request", "ter:InvalidXML"),
                    mimetype="application/soap+xml"
                )

            # Check for Probe
            probe = body.find('.//wsd:Probe', NAMESPACES)
            if probe is None:
                return Response(
                    generate_fault_response("Not a valid Probe message", "ter:InvalidArgVal"),
                    mimetype="application/soap+xml"
                )

            # Generate ProbeMatches response
            server_ip = config.get("server_ip")
            onvif_port = config.get("onvif_port", 8000)
            device_service_url = f"http://{server_ip}:{onvif_port}/onvif/device_service"
            media_service_url = f"http://{server_ip}:{onvif_port}/onvif/media_service"

            # Use OnvifService UUID if available
            device_uuid = str(uuid.uuid4())
            if onvif_service and hasattr(onvif_service, 'device_uuid'):
                device_uuid = onvif_service.device_uuid

            # Use OnvifService model if available
            model = "YoLink-Dashboard"
            if onvif_service and hasattr(onvif_service, 'device_info'):
                model = onvif_service.device_info.get("Model", "YoLink-Dashboard")

            msg_id = f"urn:uuid:{uuid.uuid4()}"
            response = f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
    <a:MessageID>{msg_id}</a:MessageID>
    <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
  </s:Header>
  <s:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <a:EndpointReference>
          <a:Address>urn:uuid:{device_uuid}</a:Address>
        </a:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
        <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/name/{model} onvif://www.onvif.org/location/Dashboard onvif://www.onvif.org/hardware/{device_uuid}</d:Scopes>
        <d:XAddrs>{device_service_url} {media_service_url}</d:XAddrs>
        <d:MetadataVersion>1</d:MetadataVersion>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>
"""
            return Response(response, mimetype="application/soap+xml")

        except Exception as e:
            logger.error(f"Error handling WS-Discovery: {e}", exc_info=True)
            return Response(
                generate_fault_response(f"Internal error: {str(e)}", "ter:InternalError"),
                mimetype="application/soap+xml"
            )

    logger.info("ONVIF routes configured")


def check_authentication(onvif_service, headers, soap_request=None) -> bool:
    """
    Check authentication using OnvifService.

    Args:
        onvif_service: OnvifService instance
        headers: HTTP headers
        soap_request: Optional SOAP request XML for WS-Security authentication

    Returns:
        bool: True if authenticated, False otherwise
    """
    if not onvif_service.authentication_required:
        return True

    try:
        # Try using OnvifService's check_authentication method if available
        if hasattr(onvif_service, '_check_authentication'):
            return onvif_service._check_authentication(soap_request)
        elif hasattr(onvif_service, 'check_authentication'):
            return onvif_service.check_authentication(headers, soap_request)

        # Fallback to simple authentication check
        auth_header = headers.get('Authorization')
        if auth_header:
            if auth_header.startswith('Basic '):
                import base64
                try:
                    auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    username, password = auth_decoded.split(':', 1)
                    return username == onvif_service.username and password == onvif_service.password
                except Exception:
                    return False

        # Check WS-Security in SOAP request as a last resort
        if soap_request and "<Security>" in soap_request and "<UsernameToken>" in soap_request:
            import re
            # Extract username
            username_match = re.search(r'<Username[^>]*>(.*?)</Username>', soap_request)
            if username_match and username_match.group(1) == onvif_service.username:
                # Check for password
                password_match = re.search(r'<Password[^>]*>(.*?)</Password>', soap_request)
                if password_match and password_match.group(1) == onvif_service.password:
                    return True

        return False

    except Exception as e:
        logger.error(f"Error checking authentication: {e}")
        return False


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
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tev="http://www.onvif.org/ver10/events/wsdl"
               xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
               xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl"
               xmlns:ter="http://www.onvif.org/ver10/error">
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
    if onvif_service and hasattr(onvif_service, 'device_info'):
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
    onvif_port = config.get("onvif_port", 8000)
    device_service_url = f"http://{server_ip}:{onvif_port}/onvif/device_service"
    media_service_url = f"http://{server_ip}:{onvif_port}/onvif/media_service"
    events_service_url = f"http://{server_ip}:{onvif_port}/onvif/events_service"
    imaging_service_url = f"http://{server_ip}:{onvif_port}/onvif/imaging_service"
    ptz_service_url = f"http://{server_ip}:{onvif_port}/onvif/ptz_service"

    capability_device = ""
    capability_media = ""
    capability_events = ""
    capability_imaging = ""
    capability_ptz = ""

    if include_capability:
        capability_device = """
<tds:Capabilities>
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
</tds:Capabilities>
"""

        capability_media = """
<tds:Capabilities>
  <tt:StreamingCapabilities>
    <tt:RTPMulticast>false</tt:RTPMulticast>
    <tt:RTP_TCP>true</tt:RTP_TCP>
    <tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
  </tt:StreamingCapabilities>
  <tt:ProfileCapabilities>
    <tt:MaximumNumberOfProfiles>3</tt:MaximumNumberOfProfiles>
  </tt:ProfileCapabilities>
</tds:Capabilities>
"""

        capability_events = """
<tds:Capabilities>
  <tt:WSSubscriptionPolicySupport>false</tt:WSSubscriptionPolicySupport>
  <tt:WSPullPointSupport>true</tt:WSPullPointSupport>
  <tt:WSPausableSubscriptionManagerInterfaceSupport>false</tt:WSPausableSubscriptionManagerInterfaceSupport>
</tds:Capabilities>
"""

        capability_imaging = """
<tds:Capabilities>
  <tt:ImageStabilization>false</tt:ImageStabilization>
</tds:Capabilities>
"""

        capability_ptz = """
<tds:Capabilities>
  <tt:EFlip>false</tt:EFlip>
  <tt:Reverse>false</tt:Reverse>
  <tt:GetCompatibleConfigurations>true</tt:GetCompatibleConfigurations>
  <tt:MoveStatus>true</tt:MoveStatus>
  <tt:StatusPosition>true</tt:StatusPosition>
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
  <tds:Service>
    <tds:Namespace>http://www.onvif.org/ver10/events/wsdl</tds:Namespace>
    <tds:XAddr>{events_service_url}</tds:XAddr>
    <tds:Version>
      <tt:Major>1</tt:Major>
      <tt:Minor>0</tt:Minor>
    </tds:Version>
    {capability_events}
  </tds:Service>
  <tds:Service>
    <tds:Namespace>http://www.onvif.org/ver20/imaging/wsdl</tds:Namespace>
    <tds:XAddr>{imaging_service_url}</tds:XAddr>
    <tds:Version>
      <tt:Major>1</tt:Major>
      <tt:Minor>0</tt:Minor>
    </tds:Version>
    {capability_imaging}
  </tds:Service>
  <tds:Service>
    <tds:Namespace>http://www.onvif.org/ver20/ptz/wsdl</tds:Namespace>
    <tds:XAddr>{ptz_service_url}</tds:XAddr>
    <tds:Version>
      <tt:Major>1</tt:Major>
      <tt:Minor>0</tt:Minor>
    </tds:Version>
    {capability_ptz}
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
    server_ip = config.get("server_ip")
    onvif_port = config.get("onvif_port", 8000)
    device_service_url = f"http://{server_ip}:{onvif_port}/onvif/device_service"
    media_service_url = f"http://{server_ip}:{onvif_port}/onvif/media_service"
    events_service_url = f"http://{server_ip}:{onvif_port}/onvif/events_service"
    imaging_service_url = f"http://{server_ip}:{onvif_port}/onvif/imaging_service"
    ptz_service_url = f"http://{server_ip}:{onvif_port}/onvif/ptz_service"

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
        <tt:Extension>
          <tt:Dot11Configuration>false</tt:Dot11Configuration>
        </tt:Extension>
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
        <tt:Extension>
          <tt:HttpFirmwareUpgrade>false</tt:HttpFirmwareUpgrade>
          <tt:HttpSystemBackup>false</tt:HttpSystemBackup>
          <tt:HttpSystemLogging>false</tt:HttpSystemLogging>
          <tt:HttpSupportInformation>false</tt:HttpSupportInformation>
        </tt:Extension>
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
        <tt:Extension>
          <tt:SupportedEAPMethods>0</tt:SupportedEAPMethods>
          <tt:MaxUsers>1</tt:MaxUsers>
          <tt:MaxUserNameLength>16</tt:MaxUserNameLength>
          <tt:MaxPasswordLength>16</tt:MaxPasswordLength>
        </tt:Extension>
      </tt:Security>
    </tt:Device>
    <tt:Media>
      <tt:XAddr>{media_service_url}</tt:XAddr>
      <tt:StreamingCapabilities>
        <tt:RTPMulticast>false</tt:RTPMulticast>
        <tt:RTP_TCP>true</tt:RTP_TCP>
        <tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
      </tt:StreamingCapabilities>
      <tt:ProfileCapabilities>
        <tt:MaximumNumberOfProfiles>3</tt:MaximumNumberOfProfiles>
      </tt:ProfileCapabilities>
      <tt:SnapshotUri>true</tt:SnapshotUri>
      <tt:Rotation>false</tt:Rotation>
      <tt:VideoSourceMode>false</tt:VideoSourceMode>
      <tt:OSD>false</tt:OSD>
    </tt:Media>
    <tt:Events>
      <tt:XAddr>{events_service_url}</tt:XAddr>
      <tt:WSSubscriptionPolicySupport>false</tt:WSSubscriptionPolicySupport>
      <tt:WSPullPointSupport>true</tt:WSPullPointSupport>
      <tt:WSPausableSubscriptionManagerInterfaceSupport>false</tt:WSPausableSubscriptionManagerInterfaceSupport>
    </tt:Events>
    <tt:Imaging>
      <tt:XAddr>{imaging_service_url}</tt:XAddr>
    </tt:Imaging>
    <tt:PTZ>
      <tt:XAddr>{ptz_service_url}</tt:XAddr>
    </tt:PTZ>
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
  <trt:Capabilities SnapshotUri="true" Rotation="false" VideoSourceMode="false" OSD="false" TemporaryOSDText="false" EXICompression="false" RuleEngine="false" IVASupport="false" ProfileCapabilities="true" MaximumNumberOfProfiles="3" />
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
        return generate_fault_response(f"Unknown service type: {service_type}")

    return generate_soap_response(action, response)


def handle_get_profiles(config: Dict[str, Any], onvif_service) -> str:
    """
    Handle GetProfiles request.
    Returns information about all available profiles.
    """
    # Always use all three profiles
    if onvif_service and hasattr(onvif_service, 'media_profiles'):
        profiles = []
        for profile in onvif_service.media_profiles:
            if hasattr(profile, 'to_dict'):
                profile_dict = profile.to_dict()
                profiles.append(profile_dict)
            else:
                profiles.append(profile)
    else:
        profiles = [
            {
                "token": "profile1",
                "name": "YoLink Main Stream",
                "resolution": {"width": config.get("width", 1920), "height": config.get("height", 1080)},
                "fps": config.get("frame_rate", 6),
                "encoding": "H264"
            },
            {
                "token": "profile2",
                "name": "YoLink Low Stream",
                "resolution": {"width": int(config.get("width", 1920)) // 2,
                               "height": int(config.get("height", 1080)) // 2},
                "fps": min(int(config.get("frame_rate", 6)), 4),
                "encoding": "H264"
            },
            {
                "token": "profile3",
                "name": "YoLink Mobile Stream",
                "resolution": {"width": int(config.get("width", 1920)) // 4,
                               "height": int(config.get("height", 1080)) // 4},
                "fps": 2,
                "encoding": "H264"
            }
        ]

    profiles_xml = ""
    for profile in profiles:
        # Handle different profile data structures
        token = profile.get("token", "")
        name = profile.get("name", "")

        # Handle nested resolution dict or direct width/height keys
        if "resolution" in profile:
            width = profile["resolution"].get("width", 1920)
            height = profile["resolution"].get("height", 1080)
        else:
            width = profile.get("width", 1920)
            height = profile.get("height", 1080)

        fps = profile.get("fps", 6)
        encoding = profile.get("encoding", "H264")

        profiles_xml += f"""
<trt:Profiles fixed="true" token="{token}">
  <tt:Name>{name}</tt:Name>
  <tt:VideoSourceConfiguration token="VideoSourceConfig_{token}">
    <tt:Name>VideoSourceConfig</tt:Name>
    <tt:UseCount>1</tt:UseCount>
    <tt:SourceToken>VideoSource</tt:SourceToken>
    <tt:Bounds height="{height}" width="{width}" y="0" x="0"/>
  </tt:VideoSourceConfiguration>
  <tt:VideoEncoderConfiguration token="VideoEncoder_{token}">
    <tt:Name>VideoEncoder</tt:Name>
    <tt:UseCount>1</tt:UseCount>
    <tt:Encoding>{encoding}</tt:Encoding>
    <tt:Resolution>
      <tt:Width>{width}</tt:Width>
      <tt:Height>{height}</tt:Height>
    </tt:Resolution>
    <tt:Quality>5</tt:Quality>
    <tt:RateControl>
      <tt:FrameRateLimit>{fps}</tt:FrameRateLimit>
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
  <tt:PTZConfiguration token="PTZConfig_{token}">
    <tt:Name>PTZConfig</tt:Name>
    <tt:UseCount>1</tt:UseCount>
    <tt:NodeToken>PTZNodeToken</tt:NodeToken>
    <tt:DefaultAbsolutePantTiltPositionSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:DefaultAbsolutePantTiltPositionSpace>
    <tt:DefaultAbsoluteZoomPositionSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:DefaultAbsoluteZoomPositionSpace>
    <tt:DefaultRelativePanTiltTranslationSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</tt:DefaultRelativePanTiltTranslationSpace>
    <tt:DefaultRelativeZoomTranslationSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace</tt:DefaultRelativeZoomTranslationSpace>
    <tt:DefaultContinuousPanTiltVelocitySpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:DefaultContinuousPanTiltVelocitySpace>
    <tt:DefaultContinuousZoomVelocitySpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:DefaultContinuousZoomVelocitySpace>
    <tt:DefaultPTZSpeed>
      <tt:PanTilt x="0.0" y="0.0" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace"/>
      <tt:Zoom x="0.0" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace"/>
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
  </tt:PTZConfiguration>
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
    Returns information about a specific profile.
    """
    # Find the requested profile
    profile = None

    if onvif_service and hasattr(onvif_service, 'media_profiles'):
        for p in onvif_service.media_profiles:
            if (hasattr(p, 'token') and p.token == token) or (hasattr(p, 'get') and p.get('token') == token):
                if hasattr(p, 'to_dict'):
                    profile = p.to_dict()
                else:
                    profile = p
                break

    if profile is None:
        # Fallback to default profile definitions
        if token == "profile1":
            profile = {
                "token": "profile1",
                "name": "YoLink Main Stream",
                "resolution": {"width": config.get("width", 1920), "height": config.get("height", 1080)},
                "fps": config.get("frame_rate", 6),
                "encoding": "H264"
            }
        elif token == "profile2":
            profile = {
                "token": "profile2",
                "name": "YoLink Low Stream",
                "resolution": {"width": int(config.get("width", 1920)) // 2,
                               "height": int(config.get("height", 1080)) // 2},
                "fps": min(int(config.get("frame_rate", 6)), 4),
                "encoding": "H264"
            }
        elif token == "profile3":
            profile = {
                "token": "profile3",
                "name": "YoLink Mobile Stream",
                "resolution": {"width": int(config.get("width", 1920)) // 4,
                               "height": int(config.get("height", 1080)) // 4},
                "fps": 2,
                "encoding": "H264"
            }
        else:
            # Default to profile1 if requested token not found
            profile = {
                "token": "profile1",
                "name": "YoLink Main Stream",
                "resolution": {"width": config.get("width", 1920), "height": config.get("height", 1080)},
                "fps": config.get("frame_rate", 6),
                "encoding": "H264"
            }

    # Handle different profile data structures
    name = profile.get("name", "")

    # Handle nested resolution dict or direct width/height keys
    if "resolution" in profile:
        width = profile["resolution"].get("width", 1920)
        height = profile["resolution"].get("height", 1080)
    else:
        width = profile.get("width", 1920)
        height = profile.get("height", 1080)

    fps = profile.get("fps", 6)
    encoding = profile.get("encoding", "H264")

    response = f"""
<trt:GetProfileResponse>
  <trt:Profile fixed="true" token="{token}">
    <tt:Name>{name}</tt:Name>
    <tt:VideoSourceConfiguration token="VideoSourceConfig_{token}">
      <tt:Name>VideoSourceConfig</tt:Name>
      <tt:UseCount>1</tt:UseCount>
      <tt:SourceToken>VideoSource</tt:SourceToken>
      <tt:Bounds height="{height}" width="{width}" y="0" x="0"/>
    </tt:VideoSourceConfiguration>
    <tt:VideoEncoderConfiguration token="VideoEncoder_{token}">
      <tt:Name>VideoEncoder</tt:Name>
      <tt:UseCount>1</tt:UseCount>
      <tt:Encoding>{encoding}</tt:Encoding>
      <tt:Resolution>
        <tt:Width>{width}</tt:Width>
        <tt:Height>{height}</tt:Height>
      </tt:Resolution>
      <tt:Quality>5</tt:Quality>
      <tt:RateControl>
        <tt:FrameRateLimit>{fps}</tt:FrameRateLimit>
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
    <tt:PTZConfiguration token="PTZConfig_{token}">
      <tt:Name>PTZConfig</tt:Name>
      <tt:UseCount>1</tt:UseCount>
      <tt:NodeToken>PTZNodeToken</tt:NodeToken>
      <tt:DefaultAbsolutePantTiltPositionSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace</tt:DefaultAbsolutePantTiltPositionSpace>
      <tt:DefaultAbsoluteZoomPositionSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace</tt:DefaultAbsoluteZoomPositionSpace>
      <tt:DefaultRelativePanTiltTranslationSpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</tt:DefaultRelativePanTiltTranslationSpace>
      <tt:DefaultRelativeZoomTranslationSpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace</tt:DefaultRelativeZoomTranslationSpace>
      <tt:DefaultContinuousPanTiltVelocitySpace>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</tt:DefaultContinuousPanTiltVelocitySpace>
      <tt:DefaultContinuousZoomVelocitySpace>http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace</tt:DefaultContinuousZoomVelocitySpace>
      <tt:DefaultPTZSpeed>
        <tt:PanTilt x="0.0" y="0.0" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace"/>
        <tt:Zoom x="0.0" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace"/>
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
    </tt:PTZConfiguration>
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
    Returns the RTSP URI for a specific profile.
    """
    # First, check the integration layer if available
    if onvif_service and hasattr(onvif_service, 'get_stream_uri'):
        uri = onvif_service.get_stream_uri(token)
        if uri:
            return generate_stream_uri_response(uri)

    # Try the integration API
    if onvif_service and hasattr(onvif_service, 'onvif_integration') and hasattr(onvif_service.onvif_integration, 'get_stream_uri'):
        uri = onvif_service.onvif_integration.get_stream_uri(token)
        if uri:
            return generate_stream_uri_response(uri)

    # Fallback to building the URI manually
    server_ip = config.get("server_ip")
    rtsp_port = config.get("rtsp_port", 554)
    stream_name = config.get("stream_name", "yolink-dashboard")

    # Add profile-specific suffix
    if token == "profile1":
        stream_suffix = "_main"
    elif token == "profile2":
        stream_suffix = "_sub"
    elif token == "profile3":
        stream_suffix = "_mobile"
    else:
        stream_suffix = ""

    # Add the suffix to the stream name
    stream_name = f"{stream_name}{stream_suffix}"

    # Get auth parameters for RTSP URL if needed
    auth_part = ""
    if onvif_service and onvif_service.authentication_required:
        auth_part = f"{onvif_service.username}:{onvif_service.password}@"
    elif config.get("onvif_auth_required", True):
        username = config.get("onvif_username", "admin")
        password = config.get("onvif_password", "123456")
        auth_part = f"{username}:{password}@"

    # Create the URI
    uri = f"rtsp://{auth_part}{server_ip}:{rtsp_port}/{stream_name}"

    return generate_stream_uri_response(uri)


def generate_stream_uri_response(uri: str) -> str:
    """Generate a SOAP response for GetStreamUri."""
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
    return generate_soap_response(
        "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
        response
    )