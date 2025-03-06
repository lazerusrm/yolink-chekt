"""
Integration helper for connecting ONVIF service with multi-profile RTSP streaming.
Provides efficient coordination between components using an event-based approach
to support Profile S compliance.
"""
import logging
import threading
import time
import queue
from typing import Dict, Any, Optional, Callable, List, Set, Tuple, Union

logger = logging.getLogger(__name__)


class OnvifStreamingIntegration:
    """
    Integration helper for ONVIF service and multi-profile RTSP streamer.
    Handles the coordination between profile selection, resolution, and streaming
    with efficient resource usage and Profile S compliance.
    """

    def __init__(self, config: Dict[str, Any], onvif_service, rtsp_streamer, renderer):
        """
        Initialize the integration helper.

        Args:
            config: Application configuration
            onvif_service: OnvifService instance
            rtsp_streamer: MultiProfileRtspStreamer instance
            renderer: DashboardRenderer instance
        """
        self.config = config
        self.onvif_service = onvif_service
        self.rtsp_streamer = rtsp_streamer
        self.renderer = renderer

        # Thread synchronization
        self.lock = threading.RLock()

        # Event queues for inter-thread communication
        self.profile_events = queue.Queue()

        # Track active and pending profiles
        self.active_profiles: Set[str] = set()
        self.pending_profiles: Set[str] = set()
        self.profile_activation_times: Dict[str, float] = {}

        # Track stream URIs for quick lookup
        self.stream_uris: Dict[str, str] = {}

        # Delayed profile activation settings
        self.activation_delay = 0.5  # seconds between profile activations
        self.activation_thread = None
        self.running = True

        # Register callbacks
        self._register_callbacks()

        # Start the main profile
        self._initialize_default_profile()

        # Start profile activation thread
        self._start_activation_thread()

        logger.info("ONVIF streaming integration initialized")

    def _register_callbacks(self) -> None:
        """Register callbacks with the ONVIF service for profile activation."""
        # Register default callback for any profile
        if hasattr(self.onvif_service, 'register_profile_callback'):
            self.onvif_service.register_profile_callback(self.on_profile_requested)

            # Register specific callbacks for each profile if needed
            self.onvif_service.register_profile_specific_callback("profile1",
                                                                 self.on_profile1_requested)
            self.onvif_service.register_profile_specific_callback("profile2",
                                                                 self.on_profile2_requested)
            self.onvif_service.register_profile_specific_callback("profile3",
                                                                 self.on_profile3_requested)

            logger.info("Profile callbacks registered with ONVIF service")
        else:
            logger.warning("ONVIF service doesn't support profile callbacks")

    def _initialize_default_profile(self) -> None:
        """Initialize the main profile immediately for faster startup."""
        self.ensure_profile_active("profile1")
        logger.info("Main profile (profile1) initialized")

        # Add the other profiles to the pending queue
        with self.lock:
            for profile in ["profile2", "profile3"]:
                if profile not in self.active_profiles and profile not in self.pending_profiles:
                    self.pending_profiles.add(profile)
                    self.profile_activation_times[profile] = time.time() + self.activation_delay * 2

        logger.info("Low and mobile profiles (profile2, profile3) queued for activation")

    def _start_activation_thread(self) -> None:
        """Start the delayed profile activation thread."""
        self.activation_thread = threading.Thread(
            target=self._process_pending_activations,
            daemon=True,
            name="profile-activator"
        )
        self.activation_thread.start()
        logger.debug("Profile activation thread started")

    def _process_pending_activations(self) -> None:
        """Process pending profile activations with rate limiting and event monitoring."""
        while self.running:
            try:
                # Check for events from the event queue
                try:
                    event_type, profile_token, event_data = self.profile_events.get(block=False)
                    self._handle_profile_event(event_type, profile_token, event_data)
                    self.profile_events.task_done()
                except queue.Empty:
                    pass  # No events in queue

                # Check for pending profiles to activate
                current_time = time.time()
                profiles_to_activate = set()

                with self.lock:
                    # Find profiles ready for activation
                    for profile_id in list(self.pending_profiles):
                        activation_time = self.profile_activation_times.get(profile_id, 0)
                        if current_time >= activation_time:
                            profiles_to_activate.add(profile_id)
                            self.pending_profiles.remove(profile_id)

                # Activate profiles outside the lock to prevent deadlocks
                for profile_id in profiles_to_activate:
                    self._activate_profile(profile_id)

                # Sleep a bit to avoid tight loop
                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Error in profile activation thread: {e}", exc_info=True)
                time.sleep(1)  # Sleep longer on error

        logger.debug("Profile activation thread stopped")

    def _handle_profile_event(self, event_type: str, profile_token: str, event_data: Any) -> None:
        """
        Handle profile-related events.

        Args:
            event_type: Type of the event
            profile_token: Profile token
            event_data: Additional event data
        """
        if event_type == "stream_started":
            logger.info(f"Stream started for profile {profile_token}")
            with self.lock:
                if profile_token not in self.active_profiles:
                    self.active_profiles.add(profile_token)
        elif event_type == "stream_stopped":
            logger.info(f"Stream stopped for profile {profile_token}")
            with self.lock:
                if profile_token in self.active_profiles:
                    self.active_profiles.remove(profile_token)
        elif event_type == "stream_error":
            logger.error(f"Stream error for profile {profile_token}: {event_data}")
            # Retry activation after a delay
            with self.lock:
                if profile_token in self.active_profiles:
                    self.active_profiles.remove(profile_token)
                if profile_token not in self.pending_profiles:
                    self.pending_profiles.add(profile_token)
                    self.profile_activation_times[profile_token] = time.time() + 5  # 5 seconds retry delay

    def on_profile_requested(self, profile_token: str) -> bool:
        """
        Handle generic profile request from ONVIF client.

        Args:
            profile_token: Profile token being requested

        Returns:
            bool: Success status
        """
        logger.info(f"ONVIF client requested profile: {profile_token}")

        with self.lock:
            # If already active, just return success
            if profile_token in self.active_profiles:
                logger.debug(f"Profile {profile_token} is already active")
                return True

            # If not pending, add to pending list with activation time
            if profile_token not in self.pending_profiles:
                self.pending_profiles.add(profile_token)

                # Calculate activation time with some jitter to prevent concurrent activations
                delay = self.activation_delay * (0.8 + 0.4 * (hash(profile_token) % 100) / 100)
                self.profile_activation_times[profile_token] = time.time() + delay

                logger.debug(f"Scheduled profile {profile_token} for activation in {delay:.2f}s")

            return True

    def on_profile1_requested(self, profile_token: str) -> bool:
        """
        Handle main profile request from ONVIF client.
        Prioritizes immediate activation for this profile.

        Args:
            profile_token: Profile token (should be "profile1")

        Returns:
            bool: Success status
        """
        # For the main profile, activate immediately
        return self.ensure_profile_active(profile_token)

    def on_profile2_requested(self, profile_token: str) -> bool:
        """
        Handle low resolution profile request from ONVIF client.

        Args:
            profile_token: Profile token (should be "profile2")

        Returns:
            bool: Success status
        """
        return self.on_profile_requested(profile_token)

    def on_profile3_requested(self, profile_token: str) -> bool:
        """
        Handle mobile profile request from ONVIF client.

        Args:
            profile_token: Profile token (should be "profile3")

        Returns:
            bool: Success status
        """
        return self.on_profile_requested(profile_token)

    def _activate_profile(self, profile_token: str) -> bool:
        """
        Activate a profile by starting the stream.

        Args:
            profile_token: Profile token to activate

        Returns:
            bool: Success status
        """
        try:
            # Validate the profile token
            if not profile_token or not isinstance(profile_token, str):
                logger.error(f"Invalid profile token: {profile_token}")
                return False

            # Start the stream for this profile
            if hasattr(self.rtsp_streamer, 'start_profile_stream'):
                logger.info(f"Starting stream for profile {profile_token}")
                success = self.rtsp_streamer.start_profile_stream(profile_token)

                # Track active profiles
                with self.lock:
                    if success:
                        self.active_profiles.add(profile_token)
                    if profile_token in self.profile_activation_times:
                        del self.profile_activation_times[profile_token]

                return success
            else:
                logger.warning("RTSP streamer does not support multi-profile streaming")
                return False

        except Exception as e:
            logger.error(f"Error activating profile {profile_token}: {e}", exc_info=True)
            return False

    def ensure_profile_active(self, profile_token: str) -> bool:
        """
        Ensure a specific profile is active and streaming.
        Unlike on_profile_requested, this method activates the profile immediately.

        Args:
            profile_token: Profile token to activate

        Returns:
            bool: Success status
        """
        with self.lock:
            # If already active, return success
            if profile_token in self.active_profiles:
                return True

            # If pending, remove from pending list
            if profile_token in self.pending_profiles:
                self.pending_profiles.remove(profile_token)
                if profile_token in self.profile_activation_times:
                    del self.profile_activation_times[profile_token]

        # Activate the profile directly
        return self._activate_profile(profile_token)

    def get_stream_uri(self, profile_token: str) -> Optional[str]:
        """
        Get the RTSP URI for a specific profile.
        Cached for better performance.

        Args:
            profile_token: Profile token

        Returns:
            Optional[str]: RTSP URI or None if profile not found
        """
        # Check cache first
        with self.lock:
            if profile_token in self.stream_uris:
                return self.stream_uris[profile_token]

        # Ensure the profile is active
        if not self.ensure_profile_active(profile_token):
            logger.warning(f"Failed to activate profile {profile_token}")
            return None

        # Determine the appropriate stream name
        server_ip = self.config.get("server_ip", "127.0.0.1")
        rtsp_port = self.config.get("rtsp_port", 554)
        base_stream_name = self.config.get("stream_name", "yolink-dashboard")

        # Get profile-specific stream name based on token
        if profile_token == "profile1":
            stream_name = f"{base_stream_name}_main"
        elif profile_token == "profile2":
            stream_name = f"{base_stream_name}_sub"
        elif profile_token == "profile3":
            stream_name = f"{base_stream_name}_mobile"
        else:
            stream_name = base_stream_name

        # Add authentication if required
        auth_part = ""
        if self.onvif_service.authentication_required:
            username = self.onvif_service.username
            password = self.onvif_service.password
            auth_part = f"{username}:{password}@"

        # Construct the full URI
        uri = f"rtsp://{auth_part}{server_ip}:{rtsp_port}/{stream_name}"

        # Cache the URI
        with self.lock:
            self.stream_uris[profile_token] = uri

        return uri

    def notify_stream_status(self, profile_token: str, status: str, error: Optional[str] = None) -> None:
        """
        Notify the integration about stream status changes.

        Args:
            profile_token: Profile token
            status: Status of the stream ('started', 'stopped', 'error')
            error: Optional error message
        """
        try:
            if status == "started":
                self.profile_events.put(("stream_started", profile_token, None))
            elif status == "stopped":
                self.profile_events.put(("stream_stopped", profile_token, None))
            elif status == "error":
                self.profile_events.put(("stream_error", profile_token, error))
        except Exception as e:
            logger.error(f"Error notifying stream status: {e}")

    def stop(self) -> None:
        """Stop the integration service and clean up resources."""
        logger.info("Stopping ONVIF streaming integration")

        # Set running flag to false to stop activation thread
        self.running = False

        # Clear profile tracking
        with self.lock:
            self.active_profiles.clear()
            self.pending_profiles.clear()
            self.profile_activation_times.clear()
            self.stream_uris.clear()

        # Clear event queue
        while not self.profile_events.empty():
            try:
                self.profile_events.get_nowait()
                self.profile_events.task_done()
            except queue.Empty:
                break

        # Wait for activation thread to finish
        if self.activation_thread and self.activation_thread.is_alive():
            try:
                self.activation_thread.join(timeout=1.0)
            except Exception as e:
                logger.error(f"Error stopping activation thread: {e}")

        logger.info("ONVIF streaming integration stopped")


def setup_integration(config: Dict[str, Any], onvif_service, rtsp_streamer, renderer) -> Optional[
    OnvifStreamingIntegration]:
    """
    Set up the integration between ONVIF service and RTSP streamer.
    This function validates that the required methods are available and creates the integration.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance
        rtsp_streamer: RTSP streamer instance
        renderer: DashboardRenderer instance

    Returns:
        Optional[OnvifStreamingIntegration]: Integration instance or None if not supported
    """
    # Verify that rtsp_streamer supports multi-profile streaming
    if not hasattr(rtsp_streamer, 'start_profile_stream'):
        logger.warning("RTSP streamer does not support multi-profile streaming")
        return None

    # Verify that onvif_service supports profile callbacks
    if not hasattr(onvif_service, 'register_profile_callback'):
        logger.warning("ONVIF service does not support profile callbacks")
        return None

    try:
        integration = OnvifStreamingIntegration(config, onvif_service, rtsp_streamer, renderer)
        logger.info("ONVIF integration with multi-profile streaming enabled")
        return integration
    except Exception as e:
        logger.error(f"Failed to set up ONVIF integration: {e}", exc_info=True)
        return None