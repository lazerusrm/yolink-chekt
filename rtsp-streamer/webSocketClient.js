/**
 * WebSocket Client for YoLink Dashboard
 * Handles connection to the WebSocket proxy server and emits events on message receipt
 */

const WebSocket = require('ws');
const EventEmitter = require('events');

class WebSocketClient extends EventEmitter {
  constructor(url) {
    super();
    this.url = url;
    this.ws = null;
    this.isConnecting = false;
    this.reconnectTimer = null;
    this.connect();
  }

  connect(attempt = 1) {
    if (this.isConnecting) return;

    this.isConnecting = true;
    console.log(`Connecting to WebSocket: ${this.url}, attempt ${attempt}`);

    try {
      this.ws = new WebSocket(this.url);

      this.ws.on('open', () => {
        console.log('Connected to dashboard WebSocket');
        this.isConnecting = false;
        this.emit('connected');
      });

      this.ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString());
          if (message.type === 'sensors-update') {
            this.emit('sensors-update', message.sensors || []);
          }
        } catch (err) {
          console.error('Error parsing WebSocket message:', err);
        }
      });

      this.ws.on('close', () => {
        console.log('WebSocket closed, reconnecting...');
        this.isConnecting = false;

        // Clear any existing reconnect timer
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
        }

        // Use exponential backoff for reconnection attempts
        const delay = Math.min(30000, 1000 * Math.pow(2, attempt - 1));
        console.log(`Will reconnect in ${delay}ms`);

        this.reconnectTimer = setTimeout(() => {
          this.connect(attempt + 1);
        }, delay);
      });

      this.ws.on('error', (err) => {
        console.error('WebSocket error:', err.message);
        // Let the close handler handle reconnection
      });
    } catch (err) {
      console.error('Error creating WebSocket connection:', err);
      this.isConnecting = false;

      // Attempt to reconnect
      const delay = Math.min(30000, 1000 * Math.pow(2, attempt - 1));
      console.log(`Error connecting. Will retry in ${delay}ms`);

      this.reconnectTimer = setTimeout(() => {
        this.connect(attempt + 1);
      }, delay);
    }
  }

  close() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      try {
        this.ws.close();
        console.log('WebSocket closed manually');
      } catch (err) {
        console.error('Error closing WebSocket:', err);
      }
      this.ws = null;
    }
  }
}

module.exports = WebSocketClient;