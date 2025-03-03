<template>
  <div class="sensor-data-container">
    <!-- Your existing sensor display code -->
  </div>
</template>

<script>
export default {
  data() {
    return {
      sensors: [],
      websocket: null
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
    if (this.websocket) {
      this.websocket.close();
    }
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
      // Determine websocket URL (use wss:// for HTTPS)
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;

      this.websocket = new WebSocket(wsUrl);

      // Handle incoming messages
      this.websocket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'sensors-update') {
            this.sensors = data.sensors;

            // Emit an event that the RTSP streamer will listen for
            this.$emit('sensors-updated', this.sensors);
          }
        } catch (error) {
          console.error('Error processing WebSocket message:', error);
        }
      };

      // Handle connection open
      this.websocket.onopen = () => {
        console.log('WebSocket connection established');
      };

      // Handle errors
      this.websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      // Handle connection close and attempt reconnection
      this.websocket.onclose = () => {
        console.log('WebSocket connection closed. Reconnecting...');
        setTimeout(() => {
          this.setupWebSocket();
        }, 5000);
      };
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
</style>