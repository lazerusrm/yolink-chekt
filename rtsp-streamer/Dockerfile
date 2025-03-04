FROM python:3.9-slim

# Install basic dependencies, including xz-utils for tar.xz extraction
RUN apt-get update && apt-get install -y \
    fonts-dejavu \
    procps \
    net-tools \
    curl \
    vim \
    file \
    xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Download and install a recent FFmpeg static binary (e.g., 6.1.1)
RUN curl -L https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz -o ffmpeg.tar.xz \
    && file ffmpeg.tar.xz | grep -q "XZ compressed" || (echo "Downloaded file is not XZ compressed" && exit 1) \
    && tar -xJf ffmpeg.tar.xz --strip-components=1 -C /usr/local/bin ffmpeg-6.1.1-amd64-static/ffmpeg ffmpeg-6.1.1-amd64-static/ffprobe \
    && rm ffmpeg.tar.xz

# Download MediaMTX v1.11.3
RUN curl -L https://github.com/bluenviron/mediamtx/releases/download/v1.11.3/mediamtx_v1.11.3_linux_amd64.tar.gz -o mediamtx.tar.gz \
    && file mediamtx.tar.gz | grep -q "gzip compressed" || (echo "Downloaded file is not a gzip archive" && exit 1) \
    && tar -xzvf mediamtx.tar.gz \
    && mv mediamtx /usr/local/bin/mediamtx \
    && rm mediamtx.tar.gz

# Create FIFO directory
RUN mkdir -p /tmp/streams

WORKDIR /app
COPY mediamtx.yml /opt/mediamtx.yml
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
EXPOSE 3001 8554 8555 3702
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]