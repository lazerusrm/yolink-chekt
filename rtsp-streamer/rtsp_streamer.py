"""
RTSP streaming service for the YoLink Dashboard RTSP Server.
"""
import os
import io
import time
import stat
import logging
import threading
import subprocess
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class RtspStreamer(threading.Thread):
    """
    RTSP streaming service using FFmpeg to convert rendered frames to a video stream.
    """

    def __init__(self, config: Dict[str, Any], renderer):
        """
        Initialize the RTSP streamer.

        Args:
            config: Application configuration
            renderer: DashboardRenderer instance to get frames from
        """
        super().__init__()
        self.config = config
        self.renderer = renderer
        self.ffmpeg_process = None
        self.daemon = True

        # FIFO pipe settings
        self.pipe_path = "/tmp/streams/dashboard_pipe"

        # Control flags
        self.running = True
        self.restart_attempts = 0
        self.max_restarts = 10
        self.retry_delay = 5

        # Ensure FIFO directory exists
        self._setup_fifo()

    def _setup_fifo(self) -> None:
        """
        Create or recreate the FIFO pipe for FFmpeg.
        """
        if not os.path.exists("/tmp/streams"):
            os.makedirs("/tmp/streams")
            logger.info("Created streams directory")

        # If path exists but is not a FIFO, recreate it
        if os.path.exists(self.pipe_path) and not stat.S_ISFIFO(os.stat(self.pipe_path).st_mode):
            os.remove(self.pipe_path)
            os.mkfifo(self.pipe_path)
            logger.info(f"Recreated FIFO at {self.pipe_path}")
        # If path doesn't exist, create a new FIFO
        elif not os.path.exists(self.pipe_path):
            os.mkfifo(self.pipe_path)
            logger.info(f"Created FIFO at {self.pipe_path}")

    def run(self) -> None:
        """
        Thread main function. Starts FFmpeg and feeds frames to it.
        """
        frame_interval = 1.0 / self.config.get("frame_rate", 6)
        logger.info(f"Starting RTSP streamer with frame rate {self.config.get('frame_rate')} FPS")

        while self.running:
            self.start_ffmpeg()

            try:
                with open(self.pipe_path, "wb") as fifo:
                    logger.info(f"Opened FIFO {self.pipe_path} for writing")

                    while self.running:
                        # Get a frame from the renderer
                        frame = self.renderer.render_frame(
                            self.config["width"],
                            self.config["height"]
                        )

                        try:
                            # Convert PIL Image to JPEG bytes
                            buf = io.BytesIO()
                            frame.save(buf, format="JPEG", quality=75)

                            # Write to FIFO
                            fifo.write(buf.getvalue())
                            fifo.flush()
                            logger.debug("Wrote frame to FIFO")

                        except BrokenPipeError as e:
                            logger.error(f"Broken pipe: {e}, restarting FFmpeg")
                            break
                        except Exception as e:
                            logger.error(f"Error writing to FIFO: {e}")

                        # Wait for next frame
                        time.sleep(frame_interval)

            except Exception as e:
                logger.error(f"Failed to open FIFO or maintain stream: {e}")

            # Handle restart logic
            if self.running and self.restart_attempts < self.max_restarts:
                logger.info(
                    f"Waiting {self.retry_delay} seconds before retrying FFmpeg "
                    f"(attempt {self.restart_attempts + 1}/{self.max_restarts})"
                )
                time.sleep(self.retry_delay)
                self.restart_stream()
            else:
                logger.error(f"Max restart attempts ({self.max_restarts}) reached, giving up.")
                self.running = False

    def start_ffmpeg(self) -> None:
        """
        Start the FFmpeg process for RTSP streaming.
        """
        rtsp_url = f"rtsp://127.0.0.1:{self.config.get('rtsp_port')}/{self.config.get('stream_name')}"

        cmd = [
            "ffmpeg",
            "-re",
            "-f", "image2pipe",
            "-framerate", str(self.config.get("frame_rate", 6)),
            "-i", self.pipe_path,
            "-c:v", "libx264",
            "-r", str(self.config.get("frame_rate", 6)),
            "-g", "12",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-b:v", "4000k",
            "-bufsize", "8000k",
            "-maxrate", "4500k",
            "-pix_fmt", "yuv420p",
            "-threads", "2",
            "-s", f"{self.config['width']}x{self.config['height']}",
            "-timeout", "60000000",
            "-reconnect", "1",
            "-reconnect_at_eof", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "10",
            "-f", "rtsp",
            "-rtsp_transport", "tcp",
            rtsp_url
        ]

        logger.info(f"Starting FFmpeg: {' '.join(cmd)}")

        try:
            self.ffmpeg_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            # Read initial output to check for immediate errors
            stderr_line = self.ffmpeg_process.stderr.readline()
            if stderr_line:
                logger.info(f"FFmpeg initial output: {stderr_line.strip()}")

            # Start monitoring thread
            threading.Thread(target=self.monitor_ffmpeg, daemon=True).start()

            # Reset restart attempts counter on successful start
            self.restart_attempts = 0

        except Exception as e:
            logger.error(f"Failed to start FFmpeg: {e}")
            self.restart_stream()

    def monitor_ffmpeg(self) -> None:
        """
        Monitor the FFmpeg process and handle unexpected exits.
        """
        if not self.ffmpeg_process:
            return

        while self.running:
            # Check if process has exited
            if self.ffmpeg_process.poll() is not None:
                exit_code = self.ffmpeg_process.poll()
                logger.error(f"FFmpeg process exited with code {exit_code}")

                # Collect any remaining output
                stdout, stderr = process.communicate(timeout=5)
                if stderr:
                    # Parse stderr for specific error conditions
                    if "Connection refused" in stderr:
                        logger.error("RTSP server connection refused. Is MediaMTX running?")
                    elif "Invalid data" in stderr:
                        logger.error("FFmpeg received invalid data from the FIFO pipe")
                    else:
                        logger.error(f"FFmpeg error: {stderr}")

                # Restart if we're still running and under max attempts
                if self.running and self.restart_attempts < self.max_restarts:
                    self.restart_stream()
                break

            time.sleep(1)

    def restart_stream(self) -> None:
        """
        Restart the FFmpeg process after a failure.
        """
        self.restart_attempts += 1

        # Check if we've hit the max restart limit
        if self.restart_attempts >= self.max_restarts:
            logger.error(f"Max restart attempts ({self.max_restarts}) reached, giving up.")
            self.running = False
            return

        # Terminate existing process if any
        if self.ffmpeg_process:
            self.ffmpeg_process.terminate()
            try:
                self.ffmpeg_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ffmpeg_process.kill()
                logger.warning("FFmpeg process killed after termination timeout")
            self.ffmpeg_process = None

        logger.info(f"Restarting FFmpeg (attempt {self.restart_attempts}/{self.max_restarts})")
        self.start_ffmpeg()

    def stop(self) -> None:
        """
        Stop the RTSP streamer.
        """
        logger.info("Stopping RTSP streamer")
        self.running = False

        if self.ffmpeg_process:
            self.ffmpeg_process.terminate()
            try:
                self.ffmpeg_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ffmpeg_process.kill()
                logger.warning("FFmpeg process killed during shutdown")