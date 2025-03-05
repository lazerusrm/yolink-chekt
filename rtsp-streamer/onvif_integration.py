"""
Integration helper for connecting ONVIF service with multi-profile RTSP streaming.
Provides efficient coordination between components using an event-based approach.
"""
import logging
import threading
import time
from typing import Dict, Any, Optional, Callable, List, Set, Tuple

logger = logging.getLogger(__name__)


class OnvifStreamingIntegration:
    """
    Integration helper for ONVIF service and multi-profile RTSP streamer.
    Handles the coordination between profile selection, resolution, and streaming
    with efficient resource usage.
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

        # Track active and pending profiles
        self.active_profiles = set()
        self.pending_profiles = set()
        self.profile_activation_times = {}

        # Delayed profile activation settings
        self.activation_delay = 0.5  # seconds
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
            # self.onvif_service.register_profile_specific_callback("profile1", self.on_profile1_requested)

            logger.info("Profile callbacks registered with ONVIF service")

    def _initialize_default_profile(self) -> None:
        """Initialize the default profile (usually the main profile)."""
        # Always start the main profile
        self.ensure_profile_active("profile1")
        logger.info("Main profile (profile1) initialized")

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
        """Process pending profile activations with rate limiting."""
        while self.running:
            try:
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
                logger.error(f"Error in profile activation thread: {e}")
                time.sleep(1)  # Sleep longer on error

        logger.debug("Profile activation thread stopped")

    def on_profile_requested(self, profile_token: str) -> bool:
        """
        Handle profile request from ONVIF client.
        Instead of immediately starting the stream, schedule it for activation
        with rate limiting to prevent resource spikes.

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
            logger.error(f"Error activating profile {profile_token}: {e}")
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

        # Activate the profile directly
        return self._activate_profile(profile_token)

    def get_stream_uri(self, profile_token: str) -> Optional[str]:
        """
        Get the RTSP URI for a specific profile.

        Args:
            profile_token: Profile token

        Returns:
            Optional[str]: RTSP URI or None if profile not found
        """
        # Ensure the profile is active
        if not self.ensure_profile_active(profile_token):
            return None

        # Return the URI with profile-specific stream name
        stream_name = None

        # Get the stream name from rtsp_streamer if available
        if hasattr(self.rtsp_streamer, 'profile_configs'):
            profile_config = self.rtsp_streamer.profile_configs.get(profile_token)
            if profile_config:
                stream_name = profile_config.get('stream_name')

        # If we couldn't get it, use standard naming convention
        if not stream_name:
            if profile_token == "profile1":
                stream_name = f"{self.onvif_service.stream_name}_main"
            elif profile_token == "profile2":
                stream_name = f"{self.onvif_service.stream_name}_low"
            elif profile_token == "profile3":
                stream_name = f"{self.onvif_service.stream_name}_mobile"
            else:
                stream_name = self.onvif_service.stream_name

        # Build the URI
        server_ip = self.onvif_service.server_ip
        rtsp_port = self.onvif_service.rtsp_port

        # Get auth parameters for RTSP URL if needed
        auth_part = ""
        if self.onvif_service.authentication_required:
            auth_part = f"{self.onvif_service.username}:{self.onvif_service.password}@"

        return f"rtsp://{auth_part}{server_ip}:{rtsp_port}/{stream_name}"

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
        logger.error(f"Failed to set up ONVIF integration: {e}")
        return None
