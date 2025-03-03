# Use an official Python slim image
FROM python:3.9-slim

# Install system dependencies (including FFmpeg)
RUN apt-get update && apt-get install -y ffmpeg && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your RTSP streamer code
COPY . .

# Expose the necessary ports (HTTP API, RTSP, WebSocket, and WS-Discovery)
EXPOSE 3001 8554 9999 3702

# Start the RTSP streamer (ensure your main entrypoint is named server.py)
CMD ["python", "server.py"]
