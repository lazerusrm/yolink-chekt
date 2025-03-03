const soap = require('soap');
const dgram = require('dgram');
const ip = require('ip');
const uuid = require('uuid');

class OnvifService {
  constructor(config) {
    this.config = config;
    this.rtspUrl = null;
    this.serverIp = config.serverIp || ip.address();
    this.onvifPort = config.onvifPort || 8555;
    this.deviceInfo = {
      manufacturer: 'YoLink',
      model: 'Dashboard-RTSP',
      firmwareVersion: '1.0.0',
      serialNumber: uuid.v4(),
      hardwareId: 'YOLINK-DASHBOARD-1'
    };
  }

  initialize(rtspUrl) {
    this.rtspUrl = rtspUrl;
    this.startSoapServer();
    this.startDiscovery();
    console.log(`ONVIF service initialized: onvif://${this.serverIp}:${this.onvifPort}`);
  }

  startSoapServer() {
    const service = {
      DeviceService: {
        DevicePort: {
          GetDeviceInformation: (args, callback) => {
            callback(null, {
              Manufacturer: this.deviceInfo.manufacturer,
              Model: this.deviceInfo.model,
              FirmwareVersion: this.deviceInfo.firmwareVersion,
              SerialNumber: this.deviceInfo.serialNumber,
              HardwareId: this.deviceInfo.hardwareId
            });
          },
          GetStreamUri: (args, callback) => {
            callback(null, {
              Uri: this.rtspUrl,
              InvalidAfterConnect: false,
              InvalidAfterReboot: false,
              Timeout: 'PT0S'
            });
          }
        }
      }
    };

    const wsdl = `
      <?xml version="1.0" encoding="UTF-8"?>
      <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                   xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
                   targetNamespace="http://www.onvif.org/ver10/device/wsdl">
        <message name="GetDeviceInformationRequest"/>
        <message name="GetDeviceInformationResponse">
          <part name="parameters" element="Manufacturer Model FirmwareVersion SerialNumber HardwareId"/>
        </message>
        <message name="GetStreamUriRequest"/>
        <message name="GetStreamUriResponse">
          <part name="parameters" element="Uri"/>
        </message>
        <portType name="DevicePort">
          <operation name="GetDeviceInformation">
            <input message="tns:GetDeviceInformationRequest"/>
            <output message="tns:GetDeviceInformationResponse"/>
          </operation>
          <operation name="GetStreamUri">
            <input message="tns:GetStreamUriRequest"/>
            <output message="tns:GetStreamUriResponse"/>
          </operation>
        </portType>
        <binding name="DeviceBinding" type="tns:DevicePort">
          <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
          <operation name="GetDeviceInformation">
            <soap:operation soapAction="http://www.onvif.org/GetDeviceInformation"/>
            <input><soap:body use="literal"/></input>
            <output><soap:body use="literal"/></output>
          </operation>
          <operation name="GetStreamUri">
            <soap:operation soapAction="http://www.onvif.org/GetStreamUri"/>
            <input><soap:body use="literal"/></input>
            <output><soap:body use="literal"/></output>
          </operation>
        </binding>
        <service name="DeviceService">
          <port name="DevicePort" binding="tns:DeviceBinding">
            <soap:address location="http://${this.serverIp}:${this.onvifPort}/onvif/device_service"/>
          </port>
        </service>
      </definitions>
    `;

    const soapServer = soap.listen(null, {
      path: '/onvif/device_service',
      port: this.onvifPort,
      services: service,
      xml: wsdl
    });

    soapServer.on('error', (err) => console.error('SOAP server error:', err));
    console.log(`SOAP server running on http://${this.serverIp}:${this.onvifPort}/onvif/device_service`);
  }

  startDiscovery() {
    const socket = dgram.createSocket('udp4');
    socket.bind(3702, () => socket.setMulticastTTL(128));

    socket.on('message', (msg, rinfo) => {
      if (msg.toString().includes('Probe')) {
        const response = `
          <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            <s:Header>
              <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
              <a:To>s:Sender</a:To>
            </s:Header>
            <s:Body>
              <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
                <d:ProbeMatch>
                  <a:EndpointReference><a:Address>urn:uuid:${this.deviceInfo.serialNumber}</a:Address></a:EndpointReference>
                  <d:Types>dn:NetworkVideoTransmitter</d:Types>
                  <d:Scopes>onvif://www.onvif.org/name/YoLinkDashboard</d:Scopes>
                  <d:XAddrs>http://${this.serverIp}:${this.onvifPort}/onvif/device_service</d:XAddrs>
                </d:ProbeMatch>
              </d:ProbeMatches>
            </s:Body>
          </s:Envelope>
        `;
        socket.send(response, 0, response.length, rinfo.port, rinfo.address);
      }
    });

    socket.on('listening', () => console.log('WS-Discovery listening on UDP 3702'));
    socket.on('error', (err) => console.error('Discovery error:', err));
    this.discoverySocket = socket;
  }

  stop() {
    if (this.discoverySocket) {
      this.discoverySocket.close();
      console.log('WS-Discovery stopped');
    }
    // SOAP server stop is handled by server shutdown in server.js
  }
}

module.exports = OnvifService;