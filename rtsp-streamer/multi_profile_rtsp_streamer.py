"""
Multi-profile RTSP streaming service for the YoLink Dashboard RTSP Server.
Supports multiple resolution profiles via MediaMTX paths.
"""
import os
import io
import time
import stat
import logging
import threading
import subprocess
from typing import Dict, Any, Optional, List

from rtsp_streamer import RtspStreamer

logger = logging.getLogger(__name__)


class MultiProfileRtspStreamer(RtspStreamer):
    """
    Multi-profile RTSP streaming service that supports different resolution outputs.
    """

    def __init__(self, config: Dict[str, Any], renderer):
        """
        Initialize the multi-profile RTSP streamer.

        Args:
            config: Application configuration
            renderer: DashboardRenderer instance to get frames from
        """
        super().__init__(config, renderer)

        # Track active streams by profile token
        self.active_streams = {}
        self.ffmpeg_processes = {}
        self.active_pipes = {}
        self.profile_configs = self._prepare_profile_configs()

        # Create FIFO pipes for each profile
        self._setup_profile_fifos()

    def _prepare_profile_configs(self) -> Dict[str, Dict[str, Any]]:
        """
        Prepare configuration for each supported profile.
        """
        profiles = {
            "profile1": {
                "width": self.config.get("width", 1920),
                "height": self.config.get("height", 1080),
                "fps": self.config.get("frame_rate", 6),
                "bitrate": self.config.get("bitrate", 500),
                "pipe_path": "/tmp/streams/dashboard_pipe_main",
                "stream_name": f"{self.config.get('stream_name', 'yolink-dashboard')}_main",
                "sensors_per_page": self.config.get("sensors_per_page", 20)
            }
        }

        # Add low-resolution profile if enabled
        if self.config.get("enable_low_res_profile", False):
            profiles["profile2"] = {
                "width": self.config.get("low_res_width", self.config.get("width", 1920) // 2),
                "height": self.config.get("low_res_height", self.config.get("height", 1080) // 2),
                "fps": self.config.get("low_res_fps", min(self.config.get("frame_rate", 6), 4)),
                "bitrate": self.config.get("low_res_bitrate", self.config.get("bitrate", 500) // 4),
                "pipe_path": "/tmp/streams/dashboard_pipe_low",
                "stream_name": f"{self.config.get('stream_name', 'yolink-dashboard')}_low",
                "sensors_per_page": self.config.get("low_res_sensors_per_page", 6)
            }

        # Add mobile profile if enabled
        if self.config.get("enable_mobile_profile", False):
            profiles["profile3"] = {
                "width": self.config.get("mobile_width", self.config.get("width", 1920) // 4),
                "height": self.config.get("mobile_height", self.config.get("height", 1080) // 4),
                "fps": self.config.get("mobile_fps", 2),
                "bitrate": self.config.get("mobile_bitrate", self.config.get("bitrate", 500) // 10),
                "pipe_path": "/tmp/streams/dashboard_pipe_mobile",
                "stream_name": f"{self.config.get('stream_name', 'yolink-dashboard')}_mobile",
                "sensors_per_page": self.config.get("mobile_sensors_per_page", 4)
            }

        return profiles

    def _setup_profile_fifos(self) -> None:
        """
        Create FIFO pipes for each profile.
        """
        if not os.path.exists("/tmp/streams"):
            os.makedirs("/tmp/streams")
            logger.info("Created streams directory")

        for profile_id, profile_config in self.profile_configs.items():
            pipe_path = profile_config["pipe_path"]

            # If path exists but is not a FIFO, recreate it
            if os.path.exists(pipe_path) and not stat.S_ISFIFO(os.stat(pipe_path).st_mode):
                os.remove(pipe_path)
                os.mkfifo(pipe_path)
                logger.info(f"Recreated FIFO for {profile_id} at {pipe_path}")
            # If path doesn't exist, create a new FIFO
            elif not os.path.exists(pipe_path):
                os.mkfifo(pipe_path)
                logger.info(f"Created FIFO for {profile_id} at {pipe_path}")

    def run(self) -> None:
        """
        Thread main function. Starts FFmpeg for the main profile and feeds frames to it.
        Additional profiles are started on demand when requested through ONVIF.
        """
        # Always start the main profile
        self.start_profile_stream("profile1")

        # Monitor and maintain running streams
        while self.running:
            time.sleep(1)

            # Check if any streams need restart
            for profile_id in list(self.active_streams.keys()):
                if profile_id in self.ffmpeg_processes and self.ffmpeg_processes[profile_id].poll() is not None:
                    logger.warning(f"FFmpeg process for {profile_id} exited unexpectedly, restarting")
                    self.start_profile_stream(profile_id)

    def start_profile_stream(self, profile_id: str) -> bool:
        """
        Start streaming for a specific profile.

        Args:
            profile_id: Profile identifier (e.g., "profile1", "profile2")

        Returns:
            bool: True if started successfully, False otherwise
        """
        if profile_id not in self.profile_configs:
            logger.error(f"Cannot start unknown profile: {profile_id}")
            return False

        profile_config = self.profile_configs[profile_id]

        # Start FFmpeg for this profile
        if not self._start_ffmpeg_for_profile(profile_id):
            return False

        # Tell the renderer to adjust for this profile's resolution
        if hasattr(self.renderer, 'set_resolution'):
            self.renderer.set_resolution(
                profile_config["width"],
                profile_config["height"],
                profile_config["sensors_per_page"]
            )

        # Start frame feeding thread for this profile
        self.active_streams[profile_id] = True
        feeding_thread = threading.Thread(
            target=self._feed_frames_to_profile,
            args=(profile_id,),
            daemon=True
        )
        feeding_thread.start()

        logger.info(
            f"Started streaming for {profile_id} at {profile_config['width']}x{profile_config['height']} with {profile_config['sensors_per_page']} sensors per page")
        return True

    def _start_ffmpeg_for_profile(self, profile_id: str) -> bool:
        """
        Start FFmpeg process for a specific profile.

        Args:
            profile_id: Profile identifier

        Returns:
            bool: True if started successfully, False otherwise
        """
        profile_config = self.profile_configs[profile_id]
        pipe_path = profile_config["pipe_path"]
        stream_name = profile_config["stream_name"]
        width = profile_config["width"]
        height = profile_config["height"]
        fps = profile_config["fps"]
        bitrate = profile_config["bitrate"]

        rtsp_url = f"rtsp://127.0.0.1:{self.config.get('rtsp_port')}/{stream_name}"

        cmd = [
            "ffmpeg",
            "-re",
            "-f", "image2pipe",
            "-vcodec", "mjpeg",  # Add this line to specify the codec
            "-framerate", str(fps),
            "-i", pipe_path,
            "-c:v", "libx264",
            "-r", str(fps),
            "-g", "12",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-b:v", f"{bitrate}k",
            "-bufsize", f"{bitrate * 2}k",
            "-maxrate", f"{int(bitrate * 1.125)}k",
            "-pix_fmt", "yuv420p",
            "-threads", "2",
            "-s", f"{width}x{height}",
            "-timeout", "60000000",
            "-reconnect", "1",
            "-reconnect_at_eof", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "10",
            "-f", "rtsp",
            "-rtsp_transport", "tcp",
            rtsp_url
        ]

        logger.info(f"Starting FFmpeg for {profile_id}: {' '.join(cmd)}")

        try:
            self.ffmpeg_processes[profile_id] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            # Read initial output to check for immediate errors
            stderr_line = self.ffmpeg_processes[profile_id].stderr.readline()
            if stderr_line:
                logger.info(f"FFmpeg initial output for {profile_id}: {stderr_line.strip()}")

            # Start monitoring thread
            threading.Thread(
                target=self._monitor_ffmpeg_for_profile,
                args=(profile_id,),
                daemon=True
            ).start()

            return True

        except Exception as e:
            logger.error(f"Failed to start FFmpeg for {profile_id}: {e}")
            return False

    def _feed_frames_to_profile(self, profile_id: str) -> None:
        """
        Feed frames to a specific profile's FIFO pipe.

        Args:
            profile_id: Profile identifier
        """
        profile_config = self.profile_configs[profile_id]
        pipe_path = profile_config["pipe_path"]
        width = profile_config["width"]
        height = profile_config["height"]
        fps = profile_config["fps"]
        frame_interval = 1.0 / fps

        try:
            with open(pipe_path, "wb") as fifo:
                self.active_pipes[profile_id] = fifo
                logger.info(f"Opened FIFO {pipe_path} for writing to {profile_id}")

                last_frame_time = time.time()

                while self.running and profile_id in self.active_streams:
                    try:
                        current_time = time.time()

                        # Check if it's time for a new frame
                        if current_time - last_frame_time >= frame_interval:
                            # Tell renderer to use this profile's configuration if needed
                            if hasattr(self.renderer, 'set_resolution'):
                                self.renderer.set_resolution(
                                    width,
                                    height,
                                    profile_config["sensors_per_page"]
                                )

                            # Get a frame from the renderer
                            frame = self.renderer.render_frame(width, height)

                            # Convert PIL Image to JPEG bytes
                            buf = io.BytesIO()
                            frame.save(buf, format="JPEG", quality=90)

                            # Write to FIFO
                            fifo.write(buf.getvalue())
                            fifo.flush()

                            last_frame_time = current_time

                        # Small sleep to avoid busy loop
                        time.sleep(min(0.01, frame_interval / 10))

                    except BrokenPipeError as e:
                        logger.error(f"Broken pipe for {profile_id}: {e}, restarting FFmpeg")
                        self._restart_profile_stream(profile_id)
                        break
                    except Exception as e:
                        logger.error(f"Error writing to FIFO for {profile_id}: {e}")
                        time.sleep(0.5)  # Brief pause before retry

        except Exception as e:
            logger.error(f"Failed to open or maintain FIFO for {profile_id}: {e}")

        finally:
            # Clean up when thread exits
            if profile_id in self.active_pipes:
                del self.active_pipes[profile_id]
            logger.info(f"Stopped feeding frames to {profile_id}")

    def _monitor_ffmpeg_for_profile(self, profile_id: str) -> None:
        """
        Monitor FFmpeg process for a specific profile.

        Args:
            profile_id: Profile identifier
        """
        if profile_id not in self.ffmpeg_processes:
            return

        process = self.ffmpeg_processes[profile_id]

        while self.running and profile_id in self.active_streams:
            # Check if process has exited
            if process.poll() is not None:
                exit_code = process.poll()
                logger.error(f"FFmpeg process for {profile_id} exited with code {exit_code}")

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

                # Restart if we're still running
                if self.running and profile_id in self.active_streams:
                    self._restart_profile_stream(profile_id)
                break

            time.sleep(1)

    def _restart_profile_stream(self, profile_id: str) -> None:
        """
        Restart a specific profile's stream after failure.

        Args:
            profile_id: Profile identifier
        """
        # Terminate existing process if any
        if profile_id in self.ffmpeg_processes and self.ffmpeg_processes[profile_id]:
            try:
                self.ffmpeg_processes[profile_id].terminate()
                self.ffmpeg_processes[profile_id].wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ffmpeg_processes[profile_id].kill()
                logger.warning(f"FFmpeg process for {profile_id} killed after termination timeout")
            finally:
                if profile_id in self.ffmpeg_processes:
                    del self.ffmpeg_processes[profile_id]

        # Restart the stream
        logger.info(f"Restarting stream for {profile_id}")
        self.start_profile_stream(profile_id)

    def stop_profile_stream(self, profile_id: str) -> None:
        """
        Stop streaming for a specific profile.

        Args:
            profile_id: Profile identifier
        """
        if profile_id not in self.active_streams:
            logger.warning(f"Cannot stop non-active profile: {profile_id}")
            return

        # Mark as inactive
        if profile_id in self.active_streams:
            del self.active_streams[profile_id]

        # Terminate FFmpeg process
        if profile_id in self.ffmpeg_processes and self.ffmpeg_processes[profile_id]:
            try:
                self.ffmpeg_processes[profile_id].terminate()
                self.ffmpeg_processes[profile_id].wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ffmpeg_processes[profile_id].kill()
                logger.warning(f"FFmpeg process for {profile_id} killed after termination timeout")

            del self.ffmpeg_processes[profile_id]

        logger.info(f"Stopped streaming for {profile_id}")

    def stop(self) -> None:
        """
        Stop all profile streams and cleanup.
        """
        logger.info("Stopping multi-profile RTSP streamer")
        self.running = False

        # Stop all active profiles
        for profile_id in list(self.active_streams.keys()):
            self.stop_profile_stream(profile_id)

        # Wait for threads to clean up
        time.sleep(0.5)

        # Close any remaining pipes
        for profile_id, pipe in list(self.active_pipes.items()):
            try:
                pipe.close()
            except Exception as e:
                logger.error(f"Error closing pipe for {profile_id}: {e}")

        logger.info("Multi-profile RTSP streamer stopped")