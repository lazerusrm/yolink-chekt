// Example of how to integrate the WebSocket handler into your YolinkChekt server
// This might need to be adapted depending on your actual server structure

const express = require('express');
const http = require('http');
const { initWebSocketServer, broadcastSensorUpdate } = require('./ws-handler');

// Create Express app and HTTP server
const app = express();
const server = http.createServer(app);

// Initialize WebSocket server
const wsServer = initWebSocketServer(server, app);

// Your existing routes and middleware would go here
// ...

// Example of how to trigger sensor updates from your existing code
// In your code where you get new sensor data, call broadcastSensorUpdate
function updateSensors(sensors) {
  // Your existing logic to update sensors
  // ...

  // Broadcast the update to WebSocket clients
  broadcastSensorUpdate(sensors);
}

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Export functions for use in other parts of your application
module.exports = {
  app,
  server,
  updateSensors
};