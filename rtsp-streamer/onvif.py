"""
ONVIF API endpoints for the YoLink Dashboard RTSP Server.
"""
import uuid
import logging
from typing import Dict, Any

from flask import Flask, request, Response

logger = logging.getLogger(__name__)


def create_onvif_routes(app: Flask, config: Dict[str, Any]) -> None:
    """
    Configure ONVIF API routes for the YoLink Dashboard RTSP Server.

    Args:
        app: Flask application
        config: Application configuration
    """

    @app.route('/onvif/device_service', methods=["POST"])
    def onvif_device_service():
        """
        Handle ONVIF device service requests.
        """
        # Extract SOAP action from headers
        soap_action = request.headers.get("SOAPAction", "")

        # Handle GetDeviceInformation request
        if "GetDeviceInformation" in soap_action:
            logger.debug("Handling ONVIF GetDeviceInformation request")
            response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Body>
    <GetDeviceInformationResponse xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Manufacturer>YoLink</Manufacturer>
      <Model>Dashboard-RTSP</Model>
      <FirmwareVersion>1.0.0</FirmwareVersion>
      <SerialNumber>{str(uuid.uuid4())}</SerialNumber>
      <HardwareId>YOLINK-DASHBOARD-1</HardwareId>
    </GetDeviceInformationResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""
            return Response(response_xml, mimetype="text/xml")

        # Handle GetStreamUri request
        elif "GetStreamUri" in soap_action:
            logger.debug("Handling ONVIF GetStreamUri request")
            rtsp_url = f"rtsp://{config['server_ip']}:{config['rtsp_port']}/{config['stream_name']}"
            response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Body>
    <GetStreamUriResponse xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Uri>{rtsp_url}</Uri>
      <InvalidAfterConnect>false</InvalidAfterConnect>
      <InvalidAfterReboot>false</InvalidAfterReboot>
      <Timeout>PT0S</Timeout>
    </GetStreamUriResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""
            return Response(response_xml, mimetype="text/xml")

        # Handle unsupported actions
        else:
            logger.warning(f"Unsupported ONVIF SOAP action: {soap_action}")
            return "Unsupported SOAP Action", 400

    logger.info("ONVIF API routes configured")