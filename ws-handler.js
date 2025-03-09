// WebSocket handler for YolinkChekt dashboard
// This file should be placed in the YolinkChekt directory

const WebSocket = require('ws');
const http = require('http');

let sensorData = []; // Store the latest sensor data
let wsServer;
let connectedClients = 0;
let lastBroadcastTime = 0;

// Initialize WebSocket server with better error handling
function initWebSocketServer(server) {
  // Create WebSocket server with ping/pong enabled
  wsServer = new WebSocket.Server({
    server,
    path: '/ws',
    clientTracking: true
  });

  console.log('WebSocket server initialized at /ws');

  // Handle WebSocket connections
  wsServer.on('connection', (ws, req) => {
    connectedClients++;
    const clientIp = req.socket.remoteAddress;
    console.log(`New WebSocket client connected from ${clientIp}. Total clients: ${connectedClients}`);

    // Send current data immediately when a client connects
    if (sensorData.length > 0) {
      try {
        ws.send(JSON.stringify({
          type: 'sensors-update',
          sensors: sensorData,
          timestamp: Date.now()
        }));
        console.log('Sent initial data to new client');
      } catch (error) {
        console.error('Error sending initial data to client:', error);
      }
    } else {
      console.log('No sensor data available to send to new client');
    }

    // Set up ping-pong to detect dead connections
    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
    });

    // Handle messages from client (mainly for debugging)
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        console.log('Received message from client:', data);

        // Handle any client commands here
        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        }
      } catch (error) {
        console.error('Error processing client message:', error);
      }
    });

    // Handle connection close
    ws.on('close', (code, reason) => {
      connectedClients--;
      console.log(`WebSocket client disconnected (${code}: ${reason}). Total clients: ${connectedClients}`);
    });

    // Handle errors
    ws.on('error', (error) => {
      console.error('WebSocket client error:', error);
      // Don't decrement client count here, it will be done in the close handler
    });
  });

  // Setup interval to check for dead connections
  const pingInterval = setInterval(() => {
    wsServer.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        console.log('Terminating inactive connection');
        return ws.terminate();
      }

      ws.isAlive = false;
      try {
        ws.ping();
      } catch (e) {
        console.error('Error sending ping:', e);
        ws.terminate();
      }
    });
  }, 30000); // Check every 30 seconds

  // Handle server errors
  wsServer.on('error', (error) => {
    console.error('WebSocket server error:', error);
  });

  // Clean up interval on server close
  wsServer.on('close', () => {
    clearInterval(pingInterval);
    console.log('WebSocket server closed');
  });

  return wsServer;
}

// Broadcast sensor updates to all connected clients with better error handling
function broadcastSensorUpdate(sensors) {
  if (!wsServer) {
    console.error('Cannot broadcast: WebSocket server not initialized');
    return;
  }

  if (!Array.isArray(sensors) || sensors.length === 0) {
    console.warn('No sensor data to broadcast');
    return;
  }

  sensorData = sensors; // Update stored sensor data
  lastBroadcastTime = Date.now();

  const message = JSON.stringify({
    type: 'sensors-update',
    sensors: sensors,
    timestamp: lastBroadcastTime
  });

  let successCount = 0;
  let errorCount = 0;

  // Send to all connected clients
  wsServer.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(message);
        successCount++;
      } catch (error) {
        console.error('Error sending to client:', error);
        errorCount++;
        // Try to close the broken connection
        try {
          client.terminate();
        } catch (e) {
          // Ignore errors during termination
        }
      }
    }
  });

  // Log broadcast results
  if (wsServer.clients.size > 0) {
    console.log(`Broadcast update to ${successCount}/${wsServer.clients.size} clients (${errorCount} errors)`);
  }
}

// Get server status information
function getStatus() {
  return {
    active: wsServer ? true : false,
    clients: connectedClients,
    lastBroadcast: lastBroadcastTime ? new Date(lastBroadcastTime).toISOString() : null,
    sensorsCount: sensorData.length
  };
}

module.exports = {
  initWebSocketServer,
  broadcastSensorUpdate,
  getStatus
};