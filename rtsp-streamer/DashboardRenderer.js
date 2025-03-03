// Replace the renderFrame method in DashboardRenderer.js with this improved version
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

  // For performance tracking
  const startTime = Date.now();
  
  if (this.alarmSensors.length > 0) {
    this.renderAlarmView(ctx, width, height);
  } else {
    this.renderNormalView(ctx, width, height);
  }

  // Add footer with timestamp
  this.renderFooter(ctx, width, height);
  
  // Performance tracking
  const renderTime = Date.now() - startTime;
  if (renderTime > 50) { // Log only if rendering takes more than 50ms
    console.log(`Frame rendered in ${renderTime}ms (frame interval: ${frameTime}ms)`);
  }
  
  // Use a consistent quality and format setting for JPEG output
  try {
    // Using lower quality (0.8) and more standard encoding options for better compatibility
    return this.canvas.toBuffer('image/jpeg', { 
      quality: 0.8,
      progressive: false,
      chromaSubsampling: '4:2:0'
    });
  } catch (err) {
    console.error('Error generating frame buffer:', err);
    // Return a fallback blank frame in case of error
    ctx.fillStyle = '#000000';
    ctx.fillRect(0, 0, width, height);
    ctx.font = '32px Arial';
    ctx.fillStyle = '#ffffff';
    ctx.fillText('Error rendering dashboard', 20, 50);
    
    try {
      return this.canvas.toBuffer('image/jpeg', { quality: 0.7 });
    } catch (fallbackErr) {
      console.error('Critical error generating fallback frame:', fallbackErr);
      // Create a minimal valid JPEG buffer if all else fails
      return Buffer.from([
        0xff, 0xd8, // SOI marker
        0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // JFIF header
        0xff, 0xdb, 0x00, 0x43, 0x00, // DQT marker
        // ... (minimal quality table - just 67 zeros for simplicity)
        ...Array(67).fill(0),
        0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x01, 0x00, 0x01, 0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, // SOF marker
        0xff, 0xc4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DHT marker
        0xff, 0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f, 0x00, // SOS marker
        0x00, // minimal image data
        0xff, 0xd9  // EOI marker
      ]);
    }
  }
}