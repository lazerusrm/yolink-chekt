"""
Integration helper for connecting ONVIF service with multi-profile RTSP streaming.
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class OnvifStreamingIntegration:
    """
    Integration helper for ONVIF service and multi-profile RTSP streamer.
    Handles the coordination between profile selection, resolution, and streaming.
    """

    def __init__(self, onvif_service, rtsp_streamer, renderer):
        """
        Initialize the integration helper.

        Args:
            onvif_service: OnvifService instance
            rtsp_streamer: MultiProfileRtspStreamer instance
            renderer: DashboardRenderer instance
        """
        self.onvif_service = onvif_service
        self.rtsp_streamer = rtsp_streamer
        self.renderer = renderer
        self.active_profile_tokens = set()

        # Register callbacks if available
        if hasattr(onvif_service, 'register_profile_callback'):
            onvif_service.register_profile_callback(self.on_profile_requested)

        # Start the main profile by default
        self.ensure_profile_active("profile1")

    def on_profile_requested(self, profile_token: str) -> bool:
        """
        Handle profile request from ONVIF client.

        Args:
            profile_token: Profile token being requested

        Returns:
            bool: Success status
        """
        logger.info(f"ONVIF client requested profile: {profile_token}")
        return self.ensure_profile_active(profile_token)

    def ensure_profile_active(self, profile_token: str) -> bool:
        """
        Ensure a specific profile is active and streaming.

        Args:
            profile_token: Profile token to activate

        Returns:
            bool: Success status
        """
        # Check if profile exists in ONVIF service
        if not hasattr(self.onvif_service, 'media_profiles'):
            logger.warning("ONVIF service has no media_profiles attribute")
            return False

        profile_found = False
        profile_config = None

        for profile in self.onvif_service.media_profiles:
            if profile.get('token') == profile_token:
                profile_found = True
                profile_config = profile
                break

        if not profile_found:
            logger.warning(f"Profile token not found in ONVIF service: {profile_token}")
            return False

        # Check if this profile is already active
        if profile_token in self.active_profile_tokens:
            logger.debug(f"Profile {profile_token} is already active")
            return True

        # Start the stream for this profile
        if hasattr(self.rtsp_streamer, 'start_profile_stream'):
            success = self.rtsp_streamer.start_profile_stream(profile_token)
            if success:
                self.active_profile_tokens.add(profile_token)

                # Update renderer resolution to match this profile
                if profile_config and hasattr(self.renderer, 'set_resolution'):
                    width = profile_config.get('resolution', {}).get('width', 1920)
                    height = profile_config.get('resolution', {}).get('height', 1080)
                    sensors_per_page = profile_config.get('sensors_per_page', 20)

                    self.renderer.set_resolution(width, height, sensors_per_page)
                    logger.info(
                        f"Updated renderer for profile {profile_token}: {width}x{height}, {sensors_per_page} sensors per page")

                return True
            else:
                logger.error(f"Failed to start stream for profile {profile_token}")
                return False
        else:
            logger.warning("RTSP streamer does not support multi-profile streaming")
            return False

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

        # If we couldn't get it from rtsp_streamer, try the ONVIF profiles
        if not stream_name and hasattr(self.onvif_service, 'media_profiles'):
            for profile in self.onvif_service.media_profiles:
                if profile.get('token') == profile_token:
                    if profile_token == "profile1":
                        stream_name = f"{self.onvif_service.stream_name}_main"
                    elif profile_token == "profile2":
                        stream_name = f"{self.onvif_service.stream_name}_low"
                    elif profile_token == "profile3":
                        stream_name = f"{self.onvif_service.stream_name}_mobile"
                    break

        # If we still don't have a stream name, use the default
        if not stream_name:
            stream_name = self.onvif_service.stream_name

        # Build the URI
        server_ip = self.onvif_service.server_ip
        rtsp_port = self.onvif_service.rtsp_port

        # Get auth parameters for RTSP URL if needed
        auth_part = ""
        if self.onvif_service.authentication_required:
            auth_part = f"{self.onvif_service.username}:{self.onvif_service.password}@"

        return f"rtsp://{auth_part}{server_ip}:{rtsp_port}/{stream_name}"


def setup_integration(config: Dict[str, Any], onvif_service, rtsp_streamer, renderer) -> Optional[
    OnvifStreamingIntegration]:
    """
    Set up the integration between ONVIF service and RTSP streamer.

    Args:
        config: Application configuration
        onvif_service: OnvifService instance
        rtsp_streamer: RTSP streamer instance
        renderer: DashboardRenderer instance

    Returns:
        Optional[OnvifStreamingIntegration]: Integration instance or None if not supported
    """
    # Only set up integration if we have multi-profile support
    multi_profile_enabled = (
            config.get("enable_low_res_profile", False) or
            config.get("enable_mobile_profile", False)
    )

    if not multi_profile_enabled:
        logger.info("Multi-profile streaming not enabled in configuration")
        return None

    # Check if the rtsp_streamer supports multi-profile streaming
    if not hasattr(rtsp_streamer, 'start_profile_stream'):
        logger.warning("RTSP streamer does not support multi-profile streaming")
        return None

    # Create and return the integration helper
    integration = OnvifStreamingIntegration(onvif_service, rtsp_streamer, renderer)
    logger.info("ONVIF integration with multi-profile streaming enabled")
    return integration