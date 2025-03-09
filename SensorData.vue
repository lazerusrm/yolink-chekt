<template>
  <div class="sensor-data-container">
    <!-- Your existing sensor display code -->
    <div v-if="connectionError" class="connection-error">
      <p><i class="fas fa-exclamation-triangle"></i> Connection error: {{ errorMessage }}</p>
      <button @click="refreshData" class="refresh-button">Refresh Now</button>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      sensors: [],
      connectionError: false,
      errorMessage: '',
      lastUpdateTime: null,
      pollingInterval: null,
      isRefreshing: false
    };
  },
  mounted() {
    // Load initial sensor data
    this.refreshData();

    // Set up polling for updates
    this.startPolling();

    // Add window event listeners for visibility changes
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
  },
  beforeDestroy() {
    // Clean up polling interval
    this.stopPolling();

    // Remove event listeners
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
  },
  methods: {
    // Start polling for updates
    startPolling() {
      // Clear any existing interval
      this.stopPolling();

      // Set up new polling interval (every 5 seconds)
      this.pollingInterval = setInterval(() => {
        // Only refresh if page is visible
        if (document.visibilityState === 'visible' && !this.isRefreshing) {
          this.refreshData();
        }
      }, 5000); // 5 second polling interval

      console.log('Started polling for sensor updates');
    },

    // Stop polling
    stopPolling() {
      if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
        this.pollingInterval = null;
        console.log('Stopped polling for sensor updates');
      }
    },

    // Handle page visibility changes
    handleVisibilityChange() {
      if (document.visibilityState === 'visible') {
        console.log('Page is now visible, refreshing data');
        // Refresh immediately when page becomes visible
        this.refreshData();

        // Restart polling if needed
        if (!this.pollingInterval) {
          this.startPolling();
        }
      } else {
        // Optionally stop polling when page is hidden to save resources
        // this.stopPolling();
      }
    },

    // Refresh sensor data
    async refreshData() {
      // Prevent multiple simultaneous refreshes
      if (this.isRefreshing) return;

      this.isRefreshing = true;

      try {
        const response = await fetch('/api/sensors');

        if (!response.ok) {
          throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (data && Array.isArray(data.sensors)) {
          this.sensors = data.sensors;
          this.lastUpdateTime = new Date();
          this.connectionError = false;
          this.errorMessage = '';

          // Emit event for other components
          this.$emit('sensors-updated', this.sensors);

          console.log(`Loaded ${this.sensors.length} sensors at ${this.lastUpdateTime.toISOString()}`);
        } else {
          console.warn('Received invalid sensor data format:', data);
        }
      } catch (error) {
        console.error('Error refreshing sensor data:', error);
        this.connectionError = true;
        this.errorMessage = error.message || 'Failed to load sensor data';
      } finally {
        this.isRefreshing = false;
      }
    },

    // Force an immediate refresh
    async forceRefresh() {
      // Stop polling temporarily
      this.stopPolling();

      // Force refresh
      await this.refreshData();

      // Restart polling
      this.startPolling();
    }
  }
};
</script>

<style scoped>
.sensor-data-container {
  /* Your existing styles here */
}

.connection-error {
  background-color: rgba(255, 59, 48, 0.1);
  color: #ff3b30;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  margin: 1rem 0;
  text-align: center;
  border: 1px solid #ff3b30;
}

.connection-error i {
  margin-right: 0.5rem;
}

.refresh-button {
  background-color: #007aff;
  color: white;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  margin-top: 0.5rem;
  cursor: pointer;
}

.refresh-button:hover {
  background-color: #0056b3;
}
</style>