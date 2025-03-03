# Use an official Python slim image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the RTSP streamer requirements and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your RTSP streamer code
COPY . .

# Expose the necessary ports (HTTP API, RTSP stream, WebSocket, WS-Discovery)
EXPOSE 3001 8554 9999 3702

# Start the server (make sure your entrypoint is named 'server.py')
CMD ["python", "server.py"]
