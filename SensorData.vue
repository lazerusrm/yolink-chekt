<template>
  <div class="sensor-data-container">
    <!-- Your existing sensor display code -->
    <div v-if="connectionError" class="connection-error">
      <p><i class="fas fa-exclamation-triangle"></i> WebSocket connection error. Reconnecting...</p>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      sensors: [],
      websocket: null,
      connectionError: false,
      reconnectAttempts: 0,
      maxReconnectAttempts: 10,
      reconnectDelay: 5000
    };
  },
  mounted() {
    // Load initial sensor data
    this.loadSensors();

    // Set up real-time updates
    this.setupWebSocket();
  },
  beforeDestroy() {
    // Clean up WebSocket connection
    this.cleanupWebSocket();
  },
  methods: {
    // Load initial sensor data
    async loadSensors() {
      try {
        const response = await fetch('/api/sensors');
        const data = await response.json();
        this.sensors = data.sensors;
      } catch (error) {
        console.error('Error loading sensors:', error);
      }
    },

    // Set up WebSocket connection for real-time updates
    setupWebSocket() {
      // Clean up any existing connection
      this.cleanupWebSocket();

      // Determine websocket URL (use wss:// for HTTPS)
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;

      console.log(`Setting up ${protocol} connection to ${wsUrl}`);

      try {
        this.websocket = new WebSocket(wsUrl);

        // Handle incoming messages
        this.websocket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'sensors-update') {
              this.sensors = data.sensors;
              this.connectionError = false;
              this.reconnectAttempts = 0;

              // Emit an event that the RTSP streamer will listen for
              this.$emit('sensors-updated', this.sensors);
            }
          } catch (error) {
            console.error('Error processing WebSocket message:', error);
          }
        };

        // Handle connection open
        this.websocket.onopen = () => {
          console.log(`WebSocket connection established via ${protocol}`);
          this.connectionError = false;
          this.reconnectAttempts = 0;
        };

        // Handle errors
        this.websocket.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.connectionError = true;
        };

        // Handle connection close and attempt reconnection
        this.websocket.onclose = (event) => {
          console.log(`WebSocket connection closed (code: ${event.code}). Reconnecting...`);
          this.connectionError = true;

          // Only attempt reconnect if we haven't exceeded max attempts
          if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.min(this.reconnectAttempts, 5);
            console.log(`Reconnect attempt ${this.reconnectAttempts} in ${delay/1000}s`);

            setTimeout(() => {
              this.setupWebSocket();
            }, delay);
          } else {
            console.error(`Maximum reconnection attempts (${this.maxReconnectAttempts}) reached.`);
          }
        };
      } catch (error) {
        console.error('Error setting up WebSocket connection:', error);
        this.connectionError = true;
      }
    },

    // Clean up WebSocket connection
    cleanupWebSocket() {
      if (this.websocket) {
        // Remove event listeners to prevent memory leaks
        this.websocket.onmessage = null;
        this.websocket.onopen = null;
        this.websocket.onerror = null;
        this.websocket.onclose = null;

        // Close the connection if not already closed
        if (this.websocket.readyState === WebSocket.OPEN ||
            this.websocket.readyState === WebSocket.CONNECTING) {
          this.websocket.close();
        }

        this.websocket = null;
      }
    },

    // Update a sensor (example)
    updateSensor(sensorId, data) {
      // Update local data
      const index = this.sensors.findIndex(s => s.id === sensorId);
      if (index !== -1) {
        this.sensors[index] = { ...this.sensors[index], ...data };
      }

      // You would typically call an API here to update the server
      // Then the server would broadcast via WebSocket to all clients
    }
  }
};
</script>

<style scoped>
.sensor-data-container {
  /* Your styles here */
}

.connection-error {
  background-color: rgba(255, 59, 48, 0.1);
  color: #ff3b30;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  margin: 1rem 0;
  text-align: center;
}

.connection-error i {
  margin-right: 0.5rem;
}
</style>