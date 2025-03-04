FROM python:3.9-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    ffmpeg \
    fonts-dejavu \
    procps \
    net-tools \
    curl \
    vim \
 && rm -rf /var/lib/apt/lists/*

# Download MediaMTX v0.20.1
RUN curl -L https://github.com/bluenviron/mediamtx/releases/latest/download/mediamtx_linux_amd64.tar.gz -o mediamtx.tar.gz \
    && tar -xzvf mediamtx.tar.gz \
    && mv mediamtx /usr/local/bin/mediamtx \
    && rm mediamtx.tar.gz

# Create FIFO directory
RUN mkdir -p /tmp/streams

WORKDIR /app

# Copy config (renamed for clarity)
COPY mediamtx.yml /opt/mediamtx.yml

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy and set entrypoint
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 3001 8554 8555 3702

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]