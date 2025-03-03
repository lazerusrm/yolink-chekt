const { createCanvas } = require('canvas');

class DashboardRenderer {
  constructor(config) {
    this.config = config;
    this.canvas = createCanvas(config.width, config.height);
    this.ctx = this.canvas.getContext('2d');
    this.sensorData = [];
    this.alarmSensors = [];
    this.currentPage = 0;
    this.totalPages = 1;
  }

  updateSensors(sensors) {
    if (!Array.isArray(sensors)) {
      console.error('Invalid sensor data: not an array');
      return;
    }
    this.sensorData = sensors;
    this.alarmSensors = sensors.filter(s =>
      ['alarm', 'leak', 'motion', 'open'].includes(s?.state)
    );
    const sensorsPerPage = 12;
    this.totalPages = Math.max(1, Math.ceil(this.sensorData.length / sensorsPerPage));
    console.log(`Updated sensors: ${this.sensorData.length}, alarms: ${this.alarmSensors.length}`);
  }

  setPage(page) {
    if (typeof page !== 'number') {
      console.error('Invalid page number:', page);
      return;
    }
    this.currentPage = page % this.totalPages;
    console.log(`Set page to ${this.currentPage + 1}/${this.totalPages}`);
  }

  renderFrame() {
    const ctx = this.ctx;
    ctx.fillStyle = '#1e1e1e';
    ctx.fillRect(0, 0, this.config.width, this.config.height);

    if (this.alarmSensors.length > 0) {
      const count = this.alarmSensors.length;
      const columns = Math.ceil(Math.sqrt(count));
      const rows = Math.ceil(count / columns);
      const cellWidth = this.config.width / columns;
      const cellHeight = this.config.height / rows;

      this.alarmSensors.forEach((sensor, index) => {
        const x = (index % columns) * cellWidth;
        const y = Math.floor(index / columns) * cellHeight;
        ctx.fillStyle = '#ff0000';
        ctx.fillRect(x, y, cellWidth, cellHeight);
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 24px Arial';
        ctx.fillText(sensor.name || `Sensor ${index + 1}`, x + 10, y + 30);
        ctx.font = '20px Arial';
        ctx.fillText(`State: ${sensor.state || 'unknown'}`, x + 10, y + 60);
        if (sensor.battery !== undefined) ctx.fillText(`Battery: ${sensor.battery}%`, x + 10, y + 90);
        if (sensor.signal !== undefined) ctx.fillText(`Signal: ${sensor.signal}`, x + 10, y + 120);
        if (sensor.temperature !== undefined) {
          ctx.fillText(`Temp: ${sensor.temperature}°${sensor.temperatureUnit || 'F'}`, x + 10, y + 150);
        }
        if (sensor.humidity !== undefined) ctx.fillText(`Humidity: ${sensor.humidity}%`, x + 10, y + 180);
      });

      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 36px Arial';
      ctx.fillText('⚠️ ALARM SENSORS ⚠️', 20, 40);
    } else {
      const sensorsPerPage = 12;
      const startIdx = this.currentPage * sensorsPerPage;
      const sensorsToShow = this.sensorData.slice(startIdx, startIdx + sensorsPerPage);
      const columns = 4;
      const rows = 3;
      const cellWidth = this.config.width / columns;
      const cellHeight = this.config.height / rows;

      sensorsToShow.forEach((sensor, index) => {
        const x = (index % columns) * cellWidth;
        const y = Math.floor(index / columns) * cellHeight;
        const bgColor = ['alarm', 'leak', 'motion', 'open'].includes(sensor.state)
          ? '#ff0000'
          : sensor.battery < 20
          ? '#ffcc00'
          : '#333333';
        ctx.fillStyle = bgColor;
        ctx.fillRect(x + 5, y + 5, cellWidth - 10, cellHeight - 10);
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 20px Arial';
        ctx.fillText(sensor.name || `Sensor ${startIdx + index + 1}`, x + 15, y + 30);
        ctx.font = '16px Arial';
        ctx.fillText(`State: ${sensor.state || 'unknown'}`, x + 15, y + 55);
        if (sensor.battery !== undefined) ctx.fillText(`Battery: ${sensor.battery}%`, x + 15, y + 80);
        if (sensor.signal !== undefined) ctx.fillText(`Signal: ${sensor.signal}`, x + 15, y + 105);
        if (sensor.temperature !== undefined) {
          ctx.fillText(`Temp: ${sensor.temperature}°${sensor.temperatureUnit || 'F'}`, x + 15, y + 130);
        }
        if (sensor.humidity !== undefined) ctx.fillText(`Humidity: ${sensor.humidity}%`, x + 15, y + 155);
      });

      ctx.fillStyle = '#ffffff';
      ctx.font = '16px Arial';
      ctx.fillText(`Page ${this.currentPage + 1} of ${this.totalPages}`, this.config.width - 150, this.config.height - 20);
    }

    ctx.fillStyle = '#ffffff';
    ctx.font = '14px Arial';
    const timestamp = new Date().toLocaleString();
    ctx.fillText(`Last Updated: ${timestamp}`, 10, this.config.height - 20);

    return this.canvas.toBuffer('image/jpeg', { quality: 0.8 });
  }
}

module.exports = DashboardRenderer;