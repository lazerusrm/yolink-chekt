"""
Multi-profile RTSP streaming service for the YoLink Dashboard RTSP Server.
Supports multiple resolution profiles via MediaMTX paths.
Optimized for resource usage and stability.
"""
import os
import io
import time
import stat
import logging
import threading
import subprocess
import weakref
from typing import Dict, Any, Optional, List, Set
from collections import defaultdict

from rtsp_streamer import RtspStreamer

logger = logging.getLogger(__name__)


class ProfileStreamMonitor:
    """Helper class to monitor a single profile stream and its resources."""

    def __init__(self, profile_id: str, pipe_path: str, stream_name: str):
        self.profile_id = profile_id
        self.pipe_path = pipe_path
        self.stream_name = stream_name
        self.ffmpeg_process = None
        self.feed_thread = None
        self.monitor_thread = None
        self.pipe_handle = None
        self.active = False
        self.thread_lock = threading.RLock()

    def is_active(self) -> bool:
        """Check if this profile stream is active."""
        with self.thread_lock:
            return self.active and self.ffmpeg_process is not None

    def cleanup(self) -> None:
        """Clean up all resources associated with this profile."""
        with self.thread_lock:
            self.active = False

            # Close pipe handle if open
            if self.pipe_handle and not self.pipe_handle.closed:
                try:
                    self.pipe_handle.close()
                except Exception as e:
                    logger.error(f"Error closing pipe for {self.profile_id}: {e}")
                self.pipe_handle = None

            # Terminate FFmpeg process
            if self.ffmpeg_process:
                try:
                    self.ffmpeg_process.terminate()
                    self.ffmpeg_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.ffmpeg_process.kill()
                    logger.warning(f"FFmpeg process for {self.profile_id} killed after termination timeout")
                except Exception as e:
                    logger.error(f"Error terminating FFmpeg for {self.profile_id}: {e}")
                self.ffmpeg_process = None


class MultiProfileRtspStreamer(RtspStreamer):
    """
    Multi-profile RTSP streaming service that supports different resolution outputs.
    Optimized for resource usage by better thread and process management.
    """

    def __init__(self, config: Dict[str, Any], renderer):
        """
        Initialize the multi-profile RTSP streamer.

        Args:
            config: Application configuration
            renderer: DashboardRenderer instance to get frames from
        """
        super().__init__(config, renderer)

        # Main synchronization lock
        self.lock = threading.RLock()

        # Profile stream monitors
        self.profile_monitors = {}

        # Active worker threads
        self.worker_threads = set()

        # Configure profiles
        self.profile_configs = self._prepare_profile_configs()

        # Create FIFO pipes for each profile
        self._setup_profile_fifos()

        # Reusable buffer for frame conversion
        self.frame_buffer = io.BytesIO()

        # Setup watchdog timer to monitor resource usage
        self._setup_watchdog()

    def _setup_watchdog(self) -> None:
        """Setup a watchdog thread to monitor resource usage."""
        self.last_watchdog_time = time.time()
        watchdog_thread = threading.Thread(target=self._watchdog_monitor, daemon=True)
        watchdog_thread.start()
        self.worker_threads.add(watchdog_thread)

    def _watchdog_monitor(self) -> None:
        """Monitor system resources and thread health."""
        check_interval = 10  # seconds

        while self.running:
            time.sleep(check_interval)

            with self.lock:
                current_time = time.time()
                self.last_watchdog_time = current_time

                # Check profile monitors for stalled processes
                for profile_id, monitor in list(self.profile_monitors.items()):
                    if monitor.is_active():
                        # Check if FFmpeg process is still running
                        if monitor.ffmpeg_process and monitor.ffmpeg_process.poll() is not None:
                            logger.warning(f"Watchdog detected stopped FFmpeg for {profile_id}, restarting")
                            self._restart_profile_stream(profile_id)

            # Prune any dead worker threads
            live_threads = {t for t in self.worker_threads if t.is_alive()}
            dead_count = len(self.worker_threads) - len(live_threads)
            if dead_count > 0:
                logger.debug(f"Watchdog pruned {dead_count} dead worker threads")
                self.worker_threads = live_threads

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
            if os.path.exists(pipe_path):
                # Check if it's a FIFO
                if not stat.S_ISFIFO(os.stat(pipe_path).st_mode):
                    os.remove(pipe_path)
                    os.mkfifo(pipe_path)
                    logger.info(f"Recreated FIFO for {profile_id} at {pipe_path}")
            else:
                # Create new FIFO
                os.mkfifo(pipe_path)
                logger.info(f"Created FIFO for {profile_id} at {pipe_path}")

            # Initialize profile monitor
            self.profile_monitors[profile_id] = ProfileStreamMonitor(
                profile_id,
                pipe_path,
                profile_config["stream_name"]
            )

    def run(self) -> None:
        """
        Thread main function. Starts FFmpeg for the main profile and feeds frames to it.
        Additional profiles are started on demand when requested through ONVIF.
        """
        try:
            # Always start the main profile
            self.start_profile_stream("profile1")

            # Main monitoring loop
            while self.running:
                time.sleep(1)

                with self.lock:
                    # Check if any active profiles need restart
                    for profile_id, monitor in self.profile_monitors.items():
                        if monitor.is_active() and monitor.ffmpeg_process and monitor.ffmpeg_process.poll() is not None:
                            logger.warning(f"FFmpeg process for {profile_id} exited unexpectedly, restarting")
                            self._restart_profile_stream(profile_id)
        except Exception as e:
            logger.error(f"Error in main streamer thread: {e}")
        finally:
            # Ensure we clean up
            self.stop()

    def start_profile_stream(self, profile_id: str) -> bool:
        """
        Start streaming for a specific profile.

        Args:
            profile_id: Profile identifier (e.g., "profile1", "profile2")

        Returns:
            bool: True if started successfully, False otherwise
        """
        with self.lock:
            if profile_id not in self.profile_configs:
                logger.error(f"Cannot start unknown profile: {profile_id}")
                return False

            # Get monitor for this profile
            monitor = self.profile_monitors.get(profile_id)
            if not monitor:
                logger.error(f"No monitor found for profile: {profile_id}")
                return False

            # If already active, just return success
            if monitor.is_active():
                logger.info(f"Profile {profile_id} is already streaming")
                return True

            # Mark as active
            monitor.active = True

            # Get profile configuration
            profile_config = self.profile_configs[profile_id]

            # Start FFmpeg for this profile
            if not self._start_ffmpeg_for_profile(profile_id):
                monitor.active = False
                return False

            # Start frame feeding thread for this profile
            feed_thread = threading.Thread(
                target=self._feed_frames_to_profile,
                args=(profile_id,),
                daemon=True
            )
            feed_thread.start()
            monitor.feed_thread = feed_thread
            self.worker_threads.add(feed_thread)

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
        # Get monitor for this profile
        monitor = self.profile_monitors.get(profile_id)
        if not monitor:
            logger.error(f"No monitor found for profile: {profile_id}")
            return False

        # Clean up any existing process first
        monitor.cleanup()

        # Get profile configuration
        profile_config = self.profile_configs[profile_id]
        pipe_path = profile_config["pipe_path"]
        stream_name = profile_config["stream_name"]
        width = profile_config["width"]
        height = profile_config["height"]
        fps = profile_config["fps"]
        bitrate = profile_config["bitrate"]

        rtsp_url = f"rtsp://127.0.0.1:{self.config.get('rtsp_port')}/{stream_name}"

        # Build FFmpeg command with optimized parameters
        cmd = [
            "ffmpeg",
            "-re",
            "-f", "image2pipe",
            "-vcodec", "mjpeg",
            "-framerate", str(fps),
            "-i", pipe_path,
            "-c:v", "libx264",
            "-r", str(fps),
            "-g", str(fps * 2),  # GOP size (2 seconds)
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-b:v", f"{bitrate}k",
            "-bufsize", f"{bitrate * 2}k",
            "-maxrate", f"{int(bitrate * 1.1)}k",
            "-pix_fmt", "yuv420p",
            "-threads", "2",  # Use 2 threads for encoding
            "-s", f"{width}x{height}",
            "-timeout", "10000000",  # 10s timeout
            "-reconnect", "1",
            "-reconnect_at_eof", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "5",  # Reduced max delay
            "-f", "rtsp",
            "-rtsp_transport", "tcp",
            rtsp_url
        ]

        logger.info(f"Starting FFmpeg for {profile_id}: {' '.join(cmd)}")

        try:
            # Start FFmpeg process
            ffmpeg_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            # Store in monitor
            monitor.ffmpeg_process = ffmpeg_process

            # Read initial output to check for immediate errors
            stderr_line = ffmpeg_process.stderr.readline().strip()
            if stderr_line:
                logger.info(f"FFmpeg initial output for {profile_id}: {stderr_line}")

            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitor_ffmpeg_for_profile,
                args=(profile_id,),
                daemon=True
            )
            monitor_thread.start()
            monitor.monitor_thread = monitor_thread
            self.worker_threads.add(monitor_thread)

            return True

        except Exception as e:
            logger.error(f"Failed to start FFmpeg for {profile_id}: {e}")
            monitor.active = False
            return False

    def _feed_frames_to_profile(self, profile_id: str) -> None:
        """
        Feed frames to a specific profile's FIFO pipe.
        Optimized to reduce memory allocations and improve stability.

        Args:
            profile_id: Profile identifier
        """
        # Get monitor and config for this profile
        monitor = self.profile_monitors.get(profile_id)
        if not monitor:
            logger.error(f"No monitor found for profile: {profile_id}")
            return

        profile_config = self.profile_configs.get(profile_id)
        if not profile_config:
            logger.error(f"No config found for profile: {profile_id}")
            return

        pipe_path = profile_config["pipe_path"]
        width = profile_config["width"]
        height = profile_config["height"]
        fps = profile_config["fps"]
        frame_interval = 1.0 / fps

        # Track frame statistics
        frames_sent = 0
        start_time = time.time()
        last_frame_time = start_time
        last_stats_time = start_time

        # Reuse buffer
        buffer = io.BytesIO()

        try:
            # Open FIFO pipe for writing
            with open(pipe_path, "wb") as fifo:
                # Store in monitor
                monitor.pipe_handle = fifo
                logger.info(f"Opened FIFO {pipe_path} for writing to {profile_id}")

                # Main frame feeding loop
                while self.running and monitor.active:
                    try:
                        current_time = time.time()

                        # Check if it's time for a new frame
                        if current_time - last_frame_time >= frame_interval:
                            # Update renderer resolution if needed
                            if hasattr(self.renderer, 'set_resolution'):
                                self.renderer.set_resolution(
                                    width,
                                    height,
                                    profile_config["sensors_per_page"]
                                )

                            # Get a frame from the renderer
                            frame = self.renderer.render_frame(width, height)

                            # Convert PIL Image to JPEG bytes efficiently
                            buffer.seek(0)
                            buffer.truncate(0)
                            frame.save(buffer, format="JPEG", quality=90, optimize=True)

                            # Write to FIFO
                            fifo.write(buffer.getvalue())
                            fifo.flush()

                            # Update frame statistics
                            frames_sent += 1
                            last_frame_time = current_time

                            # Log stats periodically
                            if current_time - last_stats_time > 60:  # Every minute
                                elapsed = current_time - last_stats_time
                                fps_actual = frames_sent / elapsed
                                logger.info(
                                    f"Profile {profile_id} stats: {fps_actual:.2f} FPS, {frames_sent} frames sent")
                                frames_sent = 0
                                last_stats_time = current_time

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
            logger.info(f"Stopped feeding frames to {profile_id}")

            # Mark as inactive if we're still the monitor for this profile
            if profile_id in self.profile_monitors and self.profile_monitors[profile_id] == monitor:
                monitor.active = False