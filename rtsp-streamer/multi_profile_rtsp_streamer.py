"""
Multi-Profile RTSP streamer for serving dashboard with different profiles.
Supports multiple resolutions and encodings for ONVIF Profile S compatibility.
Updated for latest FFmpeg version compatibility.
"""
import logging
import threading
import socket
import time
import os
import signal
import subprocess
import shlex
import uuid
import tempfile
from typing import Dict, Any, Optional, List, Tuple, Set, Callable, Union

logger = logging.getLogger(__name__)


class StreamProfile:
    """
    Configuration for a specific streaming profile.
    """
    def __init__(self,
                 token: str,
                 width: int,
                 height: int,
                 fps: int,
                 bitrate: int = 2000,
                 encoding: str = "h264",
                 stream_name: Optional[str] = None):
        """
        Initialize a stream profile.

        Args:
            token: Profile token (e.g. "profile1")
            width: Video width in pixels
            height: Video height in pixels
            fps: Target frames per second
            bitrate: Target bitrate in kbps
            encoding: Video encoding (h264, h265, etc.)
            stream_name: Stream name (default None, will be generated from token)
        """
        self.token = token
        self.width = width
        self.height = height
        self.fps = fps
        self.bitrate = bitrate
        self.encoding = encoding

        # Use provided stream name or generate from token
        if stream_name:
            self.stream_name = stream_name
        else:
            # Generate from token (e.g. profile1 -> _main, profile2 -> _sub, profile3 -> _mobile)
            if token == "profile1":
                self.stream_name = "_main"
            elif token == "profile2":
                self.stream_name = "_sub"
            elif token == "profile3":
                self.stream_name = "_mobile"
            else:
                self.stream_name = f"_{token}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "token": self.token,
            "width": self.width,
            "height": self.height,
            "fps": self.fps,
            "bitrate": self.bitrate,
            "encoding": self.encoding,
            "stream_name": self.stream_name
        }


class MultiProfileRtspStreamer(threading.Thread):
    """
    RTSP streaming server with support for multiple profile streams.
    Uses FFmpeg for transcoding between different resolutions and bitrates.
    """

    def __init__(self, config: Dict[str, Any], renderer):
        """
        Initialize the RTSP streamer.

        Args:
            config: Application configuration
            renderer: DashboardRenderer instance for frames
        """
        super().__init__(daemon=True)
        self.config = config
        self.renderer = renderer

        # Base streaming config
        self.rtsp_port = int(config.get("rtsp_port", 554))
        self.base_stream_name = config.get("stream_name", "yolink-dashboard")

        # Create profile configurations
        self.profile_configs = {}
        self._create_profile_configurations()

        # Track active streaming processes
        self.active_streams = {}
        self.stream_locks = {}

        # Add a lock for each profile
        for token in self.profile_configs:
            self.stream_locks[token] = threading.RLock()

        # Overall state
        self.running = True
        self.lock = threading.RLock()

        # Status callback for integration
        self.status_callback = None

        # Find RTSP server binary
        self.rtsp_server_path = self._find_rtsp_server()

    def _create_profile_configurations(self) -> None:
        """Create the profile configurations from the main config."""
        # Main profile (profile1) - full resolution
        main_profile = StreamProfile(
            token="profile1",
            width=self.config.get("width", 1920),
            height=self.config.get("height", 1080),
            fps=self.config.get("frame_rate", 1),
            bitrate=self.config.get("bitrate", 500),
            stream_name=f"{self.base_stream_name}_main"
        )
        self.profile_configs["profile1"] = main_profile.to_dict()

        # Secondary profile (profile2) - half resolution
        sub_profile = StreamProfile(
            token="profile2",
            width=self.config.get("width", 1920) // 2,
            height=self.config.get("height", 1080) // 2,
            fps=min(self.config.get("frame_rate", 1), 4),
            bitrate=self.config.get("bitrate", 350) // 2,
            stream_name=f"{self.base_stream_name}_sub"
        )
        self.profile_configs["profile2"] = sub_profile.to_dict()

        # Mobile profile (profile3) - quarter resolution
        mobile_profile = StreamProfile(
            token="profile3",
            width=self.config.get("width", 1920) // 4,
            height=self.config.get("height", 1080) // 4,
            fps=min(self.config.get("frame_rate", 1), 2),
            bitrate=self.config.get("bitrate", 150) // 4,
            stream_name=f"{self.base_stream_name}_mobile"
        )
        self.profile_configs["profile3"] = mobile_profile.to_dict()

        logger.info(f"Created {len(self.profile_configs)} profile configurations")

    def _feed_frames_to_stream(self, profile_token: str) -> None:
        logger.info(f"Starting frame feed thread for profile {profile_token}")

        with self.lock:
            if profile_token not in self.active_streams:
                logger.error(f"Cannot feed frames: stream {profile_token} not active")
                return

            stream_info = self.active_streams[profile_token]
            profile_config = stream_info["config"]
            pipe = stream_info["pipe"]

        width = profile_config["width"]
        height = profile_config["height"]
        fps = profile_config["fps"]
        frame_interval = 1.0 / fps

        last_frame_time = 0
        frame_count = 0
        last_frame_bytes = None  # Track the last frame's bytes

        try:
            while self.running:
                with self.lock:
                    if (profile_token not in self.active_streams or
                            not self.active_streams[profile_token].get("process") or
                            self.active_streams[profile_token]["process"].poll() is not None):
                        logger.info(f"Stream {profile_token} no longer active, stopping frame feed")
                        break

                current_time = time.time()
                if current_time - last_frame_time >= frame_interval:
                    try:
                        frame = self.renderer.render_frame(width, height)
                        frame_bytes = frame.tobytes()

                        # Skip writing if the frame hasn't changed
                        if last_frame_bytes is not None and frame_bytes == last_frame_bytes:
                            logger.debug(f"Skipping unchanged frame for {profile_token}")
                            continue

                        pipe.write(frame_bytes)
                        pipe.flush()

                        last_frame_time = current_time
                        frame_count += 1
                        last_frame_bytes = frame_bytes  # Update the last frame

                        if frame_count % 30 == 0:
                            logger.debug(f"Fed {frame_count} frames to stream {profile_token}")

                    except BrokenPipeError:
                        logger.error(f"Broken pipe for stream {profile_token}, stopping frame feed")
                        break
                    except Exception as e:
                        logger.error(f"Error feeding frame to stream {profile_token}: {e}")

                time.sleep(frame_interval / 2)

        except Exception as e:
            logger.error(f"Frame feed thread for profile {profile_token} crashed: {e}", exc_info=True)

        logger.info(f"Frame feed thread for profile {profile_token} stopped after {frame_count} frames")

    def _find_rtsp_server(self) -> Optional[str]:
        """
        Find the RTSP server binary.

        Returns:
            Optional[str]: Path to RTSP server binary or None if not found
        """
        # Check if rtsp-simple-server is available
        for path in [
            "/usr/bin/rtsp-simple-server",
            "/usr/local/bin/rtsp-simple-server",
            "rtsp-simple-server"
        ]:
            try:
                # Check if the binary exists
                process = subprocess.run([path, "-version"],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         timeout=2)
                if process.returncode == 0:
                    logger.info(f"Found RTSP server at {path}")
                    return path
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

        logger.warning("RTSP server binary not found, falling back to FFmpeg RTSP output")
        return None

    def register_status_callback(self, callback: Callable[[str, str, Optional[str]], None]) -> None:
        """
        Register a callback for stream status changes.

        Args:
            callback: Function to call when stream status changes
        """
        self.status_callback = callback

    def run(self) -> None:
        """Thread main function. Starts the RTSP server and default profile stream."""
        logger.info(f"Starting RTSP streamer on port {self.rtsp_port}")

        try:
            # Start the RTSP server if we have one
            if self.rtsp_server_path:
                self._start_rtsp_server()

            # Start the main profile by default
            self.start_profile_stream("profile1")

            # Main service loop
            while self.running:
                # Check all active streams and restart any that have stopped
                self._check_streams()
                time.sleep(1)

        except Exception as e:
            logger.error(f"Error in RTSP streamer: {e}", exc_info=True)
        finally:
            self._cleanup()

    def _start_rtsp_server(self) -> None:
        """Start the RTSP server process."""
        # Skip if we don't have an RTSP server
        if not self.rtsp_server_path:
            return

        try:
            # Create a temporary configuration file
            config_content = f"""
rtspPort: {self.rtsp_port}
protocols: [tcp]
paths:
  all:
    readUser: {self.config.get("onvif_username", "admin")}
    readPass: {self.config.get("onvif_password", "123456")}
"""

            # Write to a temp file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yml') as f:
                f.write(config_content)
                config_path = f.name

            # Start the RTSP server
            logger.info(f"Starting RTSP server with config at {config_path}")
            process = subprocess.Popen(
                [self.rtsp_server_path, config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait a second to allow the server to start
            time.sleep(1)

            # Check if the server is running
            if process.poll() is not None:
                stderr = process.stderr.read()
                logger.error(f"RTSP server failed to start: {stderr}")
                return

            # Store the process
            with self.lock:
                self.rtsp_server_process = process

            logger.info(f"RTSP server started on port {self.rtsp_port}")

        except Exception as e:
            logger.error(f"Error starting RTSP server: {e}", exc_info=True)

    def _check_streams(self) -> None:
        """Check all active streams and restart any that have stopped."""
        with self.lock:
            # Copy to avoid modification during iteration
            active_streams = dict(self.active_streams)

        for token, process_info in active_streams.items():
            process = process_info.get("process")

            # Skip if no process
            if not process:
                continue

            # Check if process is still running
            if process.poll() is not None:
                logger.warning(f"Stream process for {token} has stopped, restarting")

                # Notify about the stream stopping
                if self.status_callback:
                    self.status_callback(token, "stopped")

                # Restart the stream
                self.start_profile_stream(token)

    def start_profile_stream(self, profile_token: str) -> bool:
        """
        Start streaming a specific profile with improved reliability.

        Args:
            profile_token: Profile token to stream

        Returns:
            bool: True if stream started successfully, False otherwise
        """
        # Verify profile exists
        if profile_token not in self.profile_configs:
            logger.error(f"Unknown profile token: {profile_token}")
            return False

        # Get profile config
        profile_config = self.profile_configs[profile_token]

        # Use a lock for this profile to prevent concurrent starts/stops
        with self.stream_locks[profile_token]:
            # Check if stream is already active
            if profile_token in self.active_streams and self.active_streams[profile_token].get("process"):
                process = self.active_streams[profile_token]["process"]
                if process.poll() is None:  # Process is still running
                    logger.info(f"Stream for profile {profile_token} is already active")
                    return True

            # Start the stream
            try:
                # Prepare FFmpeg command based on profile
                cmd = self._build_ffmpeg_command(profile_config)

                # Log the command (hiding password)
                log_cmd = ' '.join(cmd).replace(self.config.get("onvif_password", "123456"), "****")
                logger.debug(f"Starting FFmpeg for profile {profile_token}: {log_cmd}")

                # Start FFmpeg process with proper pipe setup
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,  # Important: Use PIPE for stdin
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=10 * 1024 * 1024  # Use a large buffer (10MB)
                )

                # Wait a bit to see if FFmpeg crashes immediately
                time.sleep(1.0)  # Increased wait time
                if process.poll() is not None:
                    stderr = process.stderr.read().decode('utf-8', errors='replace')
                    logger.error(f"FFmpeg for profile {profile_token} failed to start: {stderr}")

                    # Notify about the error
                    if self.status_callback:
                        self.status_callback(profile_token, "error", str(stderr))

                    return False

                # Store process info
                with self.lock:
                    self.active_streams[profile_token] = {
                        "process": process,
                        "start_time": time.time(),
                        "config": profile_config,
                        "pipe": process.stdin  # Store pipe reference
                    }

                # Start a separate thread to feed frames to this stream
                threading.Thread(
                    target=self._feed_frames_to_stream,
                    args=(profile_token,),
                    daemon=True,
                    name=f"stream-{profile_token}"
                ).start()

                # Notify about successful start
                if self.status_callback:
                    self.status_callback(profile_token, "started")

                logger.info(f"Stream for profile {profile_token} started successfully")
                return True

            except Exception as e:
                logger.error(f"Error starting stream for profile {profile_token}: {e}", exc_info=True)

                # Notify about the error
                if self.status_callback:
                    self.status_callback(profile_token, "error", str(e))

                return False

    def _build_ffmpeg_command(self, profile_config: Dict[str, Any]) -> List[str]:
        """
        Build FFmpeg command for a specific profile with improved reliability.
        Updated for latest FFmpeg version compatibility.

        Args:
            profile_config: Profile configuration

        Returns:
            List[str]: FFmpeg command as a list of arguments
        """
        # Get profile parameters
        width = profile_config["width"]
        height = profile_config["height"]
        fps = profile_config["fps"]
        bitrate = profile_config["bitrate"]
        stream_name = profile_config["stream_name"]

        # Get configured transport protocol (default to TCP for reliability)
        rtsp_transport = self.config.get("rtsp_transport", "tcp").lower()

        # Create a URL for the stream - use 127.0.0.1 instead of 0.0.0.0
        auth_part = ""
        if self.config.get("onvif_auth_required", True):
            username = self.config.get("onvif_username", "admin")
            password = self.config.get("onvif_password", "123456")
            auth_part = f"{username}:{password}@"

        # Important: Use 127.0.0.1 instead of 0.0.0.0 for target connection
        # Add connection options directly in the URL for latest FFmpeg
        rtsp_url = f"rtsp://{auth_part}127.0.0.1:{self.rtsp_port}/{stream_name}"

        # Determine FFmpeg path
        ffmpeg_path = "ffmpeg"
        if os.name == 'nt':  # Windows
            ffmpeg_path = "ffmpeg.exe"

        # Build the command with parameters compatible with latest FFmpeg
        cmd = [
            ffmpeg_path,
            "-f", "rawvideo",  # Input format
            "-pix_fmt", "rgb24",  # Input pixel format
            "-s", f"{width}x{height}",  # Input size
            "-r", str(fps),  # Input frame rate
            "-i", "pipe:",  # Read from stdin

            # Add a larger input buffer for improved reliability
            "-thread_queue_size", "1024",

            # Output codec settings - use more compatible options
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-profile:v", "baseline",  # More compatible profile
            "-level", "3.0",  # Adjust level as needed

            # Bitrate control - be less aggressive with bitrate limits
            "-b:v", f"{bitrate}k",
            "-maxrate", f"{bitrate * 2}k",
            "-bufsize", f"{bitrate * 4}k",

            # Frame rate and keyframe settings
            "-r", str(fps),
            "-g", str(fps * 2),  # GOP size (2 seconds)
            "-keyint_min", str(fps),

            # Force constant framerate
            "-vsync", "cfr",

            # RTSP output settings with reliable transport
            "-f", "rtsp",
            "-rtsp_transport", rtsp_transport,

            # Add reconnection parameters instead of timeout
            "-reconnect", "1",
            "-reconnect_at_eof", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "10",  # Max 10 seconds between reconnection attempts

            # Enable protocol options for better RTSP behavior
            "-avioflags", "direct",

            # Set flush_packets to force data writing
            "-flush_packets", "1",

            # The output URL
            rtsp_url
        ]

        return cmd

    def stop_profile_stream(self, profile_token: str) -> bool:
        """
        Stop streaming a specific profile.

        Args:
            profile_token: Profile token to stop

        Returns:
            bool: True if stream stopped successfully, False otherwise
        """
        # Use a lock for this profile to prevent concurrent starts/stops
        with self.stream_locks[profile_token]:
            # Check if stream is active
            if profile_token in self.active_streams and self.active_streams[profile_token].get("process"):
                process = self.active_streams[profile_token]["process"]

                try:
                    # Try to terminate gracefully
                    process.terminate()

                    # Wait a bit for process to terminate
                    for _ in range(5):
                        if process.poll() is not None:
                            break
                        time.sleep(0.1)

                    # Force kill if still running
                    if process.poll() is None:
                        if os.name == 'nt':  # Windows
                            process.kill()
                        else:  # Unix
                            os.kill(process.pid, signal.SIGKILL)

                    # Clean up
                    with self.lock:
                        if profile_token in self.active_streams:
                            del self.active_streams[profile_token]

                    # Notify about the stop
                    if self.status_callback:
                        self.status_callback(profile_token, "stopped")

                    logger.info(f"Stream for profile {profile_token} stopped successfully")
                    return True

                except Exception as e:
                    logger.error(f"Error stopping stream for profile {profile_token}: {e}", exc_info=True)
                    return False
            else:
                logger.info(f"No active stream for profile {profile_token}")
                return True

    def restart_stream(self, profile_token: Optional[str] = None) -> bool:
        """
        Restart a specific profile stream or all streams.

        Args:
            profile_token: Profile token to restart, or None for all

        Returns:
            bool: True if stream(s) restarted successfully, False otherwise
        """
        if profile_token:
            # Restart specific profile
            self.stop_profile_stream(profile_token)
            return self.start_profile_stream(profile_token)
        else:
            # Restart all active streams
            with self.lock:
                active_tokens = list(self.active_streams.keys())

            success = True
            for token in active_tokens:
                if not self.restart_stream(token):
                    success = False

            return success

    def get_active_profiles(self) -> List[str]:
        """
        Get list of active profile tokens.

        Returns:
            List[str]: List of active profile tokens
        """
        with self.lock:
            return list(self.active_streams.keys())

    def _cleanup(self) -> None:
        """Clean up resources when stopping."""
        logger.info("Cleaning up RTSP streamer resources")

        # Stop all streams
        with self.lock:
            active_streams = list(self.active_streams.keys())

        for token in active_streams:
            self.stop_profile_stream(token)

        # Stop RTSP server if running
        with self.lock:
            if hasattr(self, 'rtsp_server_process') and self.rtsp_server_process:
                logger.info("Stopping RTSP server")
                try:
                    self.rtsp_server_process.terminate()
                    self.rtsp_server_process.wait(timeout=2)
                except Exception as e:
                    logger.error(f"Error stopping RTSP server: {e}")
                    if os.name != 'nt':  # Unix
                        try:
                            os.kill(self.rtsp_server_process.pid, signal.SIGKILL)
                        except Exception:
                            pass
                self.rtsp_server_process = None

        logger.info("RTSP streamer resources cleaned up")

    def stop(self) -> None:
        """Stop the RTSP streamer."""
        logger.info("Stopping RTSP streamer")
        self.running = False
        self._cleanup()