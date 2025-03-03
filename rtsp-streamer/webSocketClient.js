const WebSocket = require('ws');
const EventEmitter = require('events');

class WebSocketClient extends EventEmitter {
  constructor(url) {
    super();
    this.url = url;
    this.ws = null;
    this.connect();
  }

  connect(attempt = 1) {
    console.log(`Connecting to WebSocket: ${this.url}, attempt ${attempt}`);
    this.ws = new WebSocket(this.url);

    this.ws.on('open', () => {
      console.log('Connected to dashboard WebSocket');
    });

    this.ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        if (message.type === 'sensors-update') {
          console.log('Received sensors-update message');
          this.emit('sensors-update', message.sensors || []);
        }
      } catch (err) {
        console.error('Error parsing WebSocket message:', err);
      }
    });

    this.ws.on('close', () => {
      console.log('WebSocket closed, reconnecting...');
      const delay = Math.min(5000, 1000 * Math.pow(2, attempt - 1)); // Exponential backoff
      setTimeout(() => this.connect(attempt + 1), delay);
    });

    this.ws.on('error', (err) => {
      console.error('WebSocket error:', err.message);
    });
  }

  close() {
    if (this.ws) {
      this.ws.close();
      console.log('WebSocket closed manually');
    }
  }
}

module.exports = WebSocketClient;