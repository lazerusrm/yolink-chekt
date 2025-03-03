# Use an official Python slim image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the RTSP streamer code
COPY . .

# Expose the ports used by the RTSP streamer
EXPOSE 3001 8554 9999 3702

# Start the RTSP streamer server (adjust the filename if necessary)
CMD ["python", "server.py"]
