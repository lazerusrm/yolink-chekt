cat > /tmp/DashboardRenderer.js << 'EOF'
const { createCanvas } = require('canvas');

class DashboardRenderer {
  constructor(config) {
    this.config = config;
    this.canvas = createCanvas(config.width || 1920, config.height || 1080);
    this.ctx = this.canvas.getContext('2d');
    this.sensorData = [];
    this.alarmSensors = [];
    this.currentPage = 0;
    this.totalPages = 1;
    this.lastRenderTime = Date.now();
  }

  updateSensors(sensors) {
    if (!Array.isArray(sensors)) {
      console.error('Invalid sensor data: not an array');
      return;
    }
    
    this.sensorData = sensors;
    
    // Filter for sensors in alarm state
    this.alarmSensors = sensors.filter(s => {
      if (!s) return false;
      
      // Check different types of alarm states
      if (['alarm', 'leak', 'motion', 'open'].includes(s.state)) return true;
      
      // Check for COSmokeSensor unexpected state
      if (s.type === 'COSmokeSensor' && 
          s.state && 
          typeof s.state === 'object' && 
          (s.state.smokeAlarm || s.state.gasAlarm || s.state.unexpected)) {
        return true;
      }
      
      // Check for low battery (level 1 or lower)
      if (s.battery !== undefined && s.battery <= 1) return true;
      
      return false;
    });
    
    // Calculate total pages based on sensors that need to be displayed
    const sensorsPerPage = 12;
    this.totalPages = Math.max(1, Math.ceil(this.sensorData.length / sensorsPerPage));
    
    // Make sure current page is valid
    if (this.currentPage >= this.totalPages) {
      this.currentPage = 0;
    }
    
    // Log update info
    console.log(`Updated sensors: ${this.sensorData.length}, alarms: ${this.alarmSensors.length}, pages: ${this.totalPages}`);
  }

  setPage(page) {
    if (typeof page !== 'number') {
      console.error('Invalid page number:', page);
      return;
    }
    
    this.currentPage = Math.max(0, Math.min(page, this.totalPages - 1));
    console.log(`Set page to ${this.currentPage + 1}/${this.totalPages}`);
  }

  renderFrame() {
    const ctx = this.ctx;
    const now = Date.now();
    const frameTime = now - this.lastRenderTime;
    this.lastRenderTime = now;
    
    // Calculate effective dimensions
    const width = this.config.width || 1920;
    const height = this.config.height || 1080;
    
    // Clear canvas with dark background
    ctx.fillStyle = '#1e1e1e';
    ctx.fillRect(0, 0, width, height);

    // For performance tracking (optional)
    const startTime = Date.now();
    
    if (this.alarmSensors.length > 0) {
      this.renderAlarmView(ctx, width, height);
    } else {
      this.renderNormalView(ctx, width, height);
    }

    // Add footer with timestamp
    this.renderFooter(ctx, width, height);
    
    // Performance tracking (optional)
    const renderTime = Date.now() - startTime;
    if (renderTime > 50) { // Log only if rendering takes more than 50ms
      console.log(`Frame rendered in ${renderTime}ms (frame interval: ${frameTime}ms)`);
    }
    
    return this.canvas.toBuffer('image/jpeg', { quality: 0.85 });
  }

  renderAlarmView(ctx, width, height) {
    // Red background for alarm state
    ctx.fillStyle = '#ff0000';
    ctx.fillRect(0, 0, width, height);
    
    // Header
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 36px Arial';
    ctx.fillText('⚠️ ALARM SENSORS ⚠️', 20, 40);
    
    // Calculate grid layout
    const count = this.alarmSensors.length;
    const columns = Math.min(3, Math.ceil(Math.sqrt(count)));
    const rows = Math.ceil(count / columns);
    const cellWidth = width / columns;
    const cellHeight = Math.min(180, (height - 60) / rows);

    // Render each alarm sensor
    this.alarmSensors.forEach((sensor, index) => {
      if (!sensor) return;
      
      const x = (index % columns) * cellWidth;
      const y = 60 + Math.floor(index / columns) * cellHeight;
      
      // Sensor background
      ctx.fillStyle = '#d70000';
      ctx.fillRect(x + 10, y + 5, cellWidth - 20, cellHeight - 15);
      
      // Sensor name and state
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 24px Arial';
      
      // Truncate name if too long
      const name = sensor.name || `Sensor ${index + 1}`;
      const maxNameWidth = cellWidth - 40;
      let displayName = name;
      
      ctx.font = 'bold 24px Arial';
      if (ctx.measureText(name).width > maxNameWidth) {
        // Truncate and add ellipsis
        for (let i = name.length; i > 3; i--) {
          const truncated = name.substring(0, i) + '...';
          if (ctx.measureText(truncated).width <= maxNameWidth) {
            displayName = truncated;
            break;
          }
        }
      }
      
      ctx.fillText(displayName, x + 20, y + 35);
      
      // Sensor details
      ctx.font = '20px Arial';
      let yOffset = 70;
      
      // Render state differently based on sensor type
      if (sensor.type === 'COSmokeSensor' && typeof sensor.state === 'object') {
        if (sensor.state.smokeAlarm) {
          ctx.fillText(`State: SMOKE DETECTED!`, x + 20, y + yOffset);
        } else if (sensor.state.gasAlarm) {
          ctx.fillText(`State: GAS DETECTED!`, x + 20, y + yOffset);
        } else if (sensor.state.unexpected) {
          ctx.fillText(`State: ALERT!`, x + 20, y + yOffset);
        } else {
          ctx.fillText(`State: ${JSON.stringify(sensor.state)}`, x + 20, y + yOffset);
        }
      } else {
        ctx.fillText(`State: ${sensor.state}`, x + 20, y + yOffset);
      }
      
      yOffset += 30;
      
      // Show battery if available
      if (sensor.battery !== undefined) {
        const batteryText = sensor.battery <= 1 ? 
          `Battery: ${sensor.battery}% (LOW!)` : 
          `Battery: ${sensor.battery}%`;
        ctx.fillText(batteryText, x + 20, y + yOffset);
        yOffset += 30;
      }
      
      // Show signal if available
      if (sensor.signal !== undefined && sensor.signal !== 'unknown') {
        ctx.fillText(`Signal: ${sensor.signal}`, x + 20, y + yOffset);
        yOffset += 30;
      }
      
      // Show temperature if available
      if (sensor.temperature !== undefined && sensor.temperature !== 'unknown') {
        ctx.fillText(`Temp: ${sensor.temperature}°${sensor.temperatureUnit || 'F'}`, x + 20, y + yOffset);
        yOffset += 30;
      }
      
      // Show humidity if available
      if (sensor.humidity !== undefined && sensor.humidity !== 'unknown') {
        ctx.fillText(`Humidity: ${sensor.humidity}%`, x + 20, y + yOffset);
      }
    });
  }

  renderNormalView(ctx, width, height) {
    // Calculate visible sensors for current page
    const sensorsPerPage = 12;
    const startIdx = this.currentPage * sensorsPerPage;
    const sensorsToShow = this.sensorData.slice(startIdx, startIdx + sensorsPerPage);
    
    // Calculate grid layout
    const columns = 4;
    const rows = 3;
    const cellWidth = width / columns;
    const cellHeight = height / rows;

    // Page indicator
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 24px Arial';
    ctx.fillText(`YoLink Dashboard - Page ${this.currentPage + 1} of ${this.totalPages}`, 20, 40);
    
    // Render each sensor
    sensorsToShow.forEach((sensor, index) => {
      if (!sensor) return;
      
      const x = (index % columns) * cellWidth;
      const y = 60 + Math.floor(index / columns) * (cellHeight - 20);
      
      // Determine background color based on state
      let bgColor = '#333333'; // Default
      
      // Alarm states
      if (['alarm', 'leak', 'motion', 'open'].includes(sensor.state)) {
        bgColor = '#ff0000';
      } 
      // CO/Smoke sensor alerts
      else if (sensor.type === 'COSmokeSensor' && 
               sensor.state && 
               typeof sensor.state === 'object' && 
               (sensor.state.smokeAlarm || sensor.state.gasAlarm || sensor.state.unexpected)) {
        bgColor = '#ff0000';
      }
      // Low battery warning
      else if (sensor.battery !== undefined && sensor.battery <= 1) {
        bgColor = '#ffcc00';
      }
      // Outlet/switch states
      else if (sensor.state === 'closed') {
        bgColor = '#006600'; // Dark green for closed/off
      }
      else if (sensor.state === 'open') {
        bgColor = '#009900'; // Brighter green for open/on
      }
      
      // Sensor cell background
      ctx.fillStyle = bgColor;
      ctx.fillRect(x + 10, y + 5, cellWidth - 20, cellHeight - 25);
      
      // Sensor name with truncation if needed
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 20px Arial';
      
      const name = sensor.name || `Sensor ${startIdx + index + 1}`;
      const maxNameWidth = cellWidth - 40;
      let displayName = name;
      
      if (ctx.measureText(name).width > maxNameWidth) {
        // Truncate and add ellipsis
        for (let i = name.length; i > 3; i--) {
          const truncated = name.substring(0, i) + '...';
          if (ctx.measureText(truncated).width <= maxNameWidth) {
            displayName = truncated;
            break;
          }
        }
      }
      
      ctx.fillText(displayName, x + 20, y + 30);
      
      // Sensor type
      ctx.font = '16px Arial';
      ctx.fillText(`Type: ${sensor.type || 'unknown'}`, x + 20, y + 55);
      
      // Sensor state
      let stateText = "unknown";
      
      if (typeof sensor.state === 'object') {
        if (sensor.type === 'COSmokeSensor') {
          if (sensor.state.smokeAlarm) stateText = "SMOKE ALARM";
          else if (sensor.state.gasAlarm) stateText = "GAS ALARM";
          else if (sensor.state.unexpected) stateText = "ALERT";
          else stateText = "normal";
        } else if (sensor.state.lock) {
          stateText = sensor.state.lock;
        } else {
          stateText = JSON.stringify(sensor.state).substring(0, 15);
        }
      } else if (sensor.state !== undefined) {
        stateText = sensor.state.toString();
      }
      
      ctx.fillText(`State: ${stateText}`, x + 20, y + 80);
      
      // Additional sensor information
      let yOffset = 105;
      
      // Show battery if available
      if (sensor.battery !== undefined && sensor.battery !== "unknown") {
        const batteryColor = sensor.battery <= 1 ? '#ff6666' : '#ffffff';
        ctx.fillStyle = batteryColor;
        ctx.fillText(`Battery: ${sensor.battery}%`, x + 20, y + yOffset);
        ctx.fillStyle = '#ffffff';
        yOffset += 25;
      }
      
      // Show signal if available
      if (sensor.signal !== undefined && sensor.signal !== "unknown") {
        ctx.fillText(`Signal: ${sensor.signal}`, x + 20, y + yOffset);
        yOffset += 25;
      }
      
      // Show temperature if available
      if (sensor.temperature !== undefined && sensor.temperature !== "unknown") {
        ctx.fillText(`Temp: ${sensor.temperature}°${sensor.temperatureUnit || 'F'}`, x + 20, y + yOffset);
        yOffset += 25;
      }
      
      // Show humidity if available
      if (sensor.humidity !== undefined && sensor.humidity !== "unknown") {
        ctx.fillText(`Humidity: ${sensor.humidity}%`, x + 20, y + yOffset);
      }
      
      // Show last seen if available
      if (sensor.last_seen && sensor.last_seen !== "never") {
        const lastSeenTime = sensor.last_seen.split(' ')[1] || sensor.last_seen;
        ctx.font = '12px Arial';
        ctx.fillText(`Last: ${lastSeenTime}`, x + 20, y + cellHeight - 35);
      }
    });
  }

  renderFooter(ctx, width, height) {
    // Add footer with timestamp and system information
    ctx.fillStyle = '#333333';
    ctx.fillRect(0, height - 30, width, 30);
    
    // Current time
    ctx.fillStyle = '#ffffff';
    ctx.font = '14px Arial';
    const timestamp = new Date().toLocaleString();
    ctx.fillText(`Last Updated: ${timestamp}`, 10, height - 10);
    
    // System information on the right
    const alarmText = this.alarmSensors.length > 0 ? 
      `⚠️ ${this.alarmSensors.length} ALARM(S) ACTIVE` : 
      'System Normal';
    ctx.fillText(alarmText, width - ctx.measureText(alarmText).width - 20, height - 10);
    
    // Center - sensor stats
    const sensorStats = `Active Sensors: ${this.sensorData.filter(s => s.last_seen && s.last_seen.includes('2025')).length}/${this.sensorData.length}`;
    ctx.fillText(sensorStats, (width - ctx.measureText(sensorStats).width) / 2, height - 10);
  }
}

module.exports = DashboardRenderer;
EOF