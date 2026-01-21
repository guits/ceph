"""LED control handler for the API.

This module provides a clean interface for handling LED operations
on chassis and drives.
"""
from typing import Dict, Any, Optional, Callable
from urllib.error import HTTPError
from ceph_node_proxy.util import get_logger


class LedHandler:
    """Handles LED control operations for chassis and drives."""

    def __init__(self, backend: Any):
        """Initialize LED handler.
        
        Args:
            backend: The system backend that implements LED operations
        """
        self.log = get_logger(__name__)
        self.backend = backend

    def validate_led_type(self, led_type: Optional[str]) -> None:
        """Validate that a LED type is provided and valid.
        
        Args:
            led_type: The LED type ('chassis' or 'drive')
            
        Raises:
            ValueError: If LED type is invalid or missing
        """
        if not led_type:
            raise ValueError("LED type must be provided (either 'chassis' or 'drive')")

        if led_type not in ['chassis', 'drive']:
            raise ValueError("LED type must be 'chassis' or 'drive'")

    def validate_drive_id(self, drive_id: Optional[str]) -> None:
        """Validate that a drive ID is provided and exists.
        
        Args:
            drive_id: The drive identifier
            
        Raises:
            ValueError: If drive ID is invalid or not found
        """
        if not drive_id:
            raise ValueError("A valid device ID must be provided")

        if drive_id not in self.backend.get_storage():
            raise ValueError(f"Drive ID '{drive_id}' not found")

    def validate_led_state(self, state: Optional[str]) -> None:
        """Validate that the LED state is valid.
        
        Args:
            state: The desired LED state
            
        Raises:
            ValueError: If state is invalid
        """
        if not state or state not in ['on', 'off']:
            raise ValueError("State must be provided and have a valid value (on|off)")

    def get_led_operation(self, led_type: str, state: str) -> Callable:
        """Get the appropriate LED operation function.
        
        Args:
            led_type: Type of LED ('chassis' or 'drive')
            state: Desired state ('on' or 'off')
            
        Returns:
            The appropriate backend function for the operation
        """
        if led_type == 'drive':
            return self.backend.device_led_on if state == 'on' else self.backend.device_led_off
        else:
            return self.backend.chassis_led_on if state == 'on' else self.backend.chassis_led_off

    def get_led_status(self, led_type: str, drive_id: Optional[str] = None) -> Dict[str, Any]:
        """Get the current status of a LED.
        
        Args:
            led_type: Type of LED ('chassis' or 'drive')
            drive_id: Drive identifier (required for drive LEDs)
            
        Returns:
            Dictionary with LED status information
            
        Raises:
            HTTPError: If the backend operation fails
        """
        try:
            if led_type == 'drive':
                if not drive_id:
                    raise ValueError("Drive ID required for drive LED status")
                return self.backend.get_device_led(drive_id)
            else:
                return self.backend.get_chassis_led()
        except HTTPError as e:
            self.log.error(f"Failed to get {led_type} LED status: {e}")
            raise

    def set_led_state(self, led_type: str, state: str, 
                      drive_id: Optional[str] = None) -> Dict[str, Any]:
        """Set the state of a LED.
        
        Args:
            led_type: Type of LED ('chassis' or 'drive')
            state: Desired state ('on' or 'off')
            drive_id: Drive identifier (required for drive LEDs)
            
        Returns:
            Dictionary with operation result
            
        Raises:
            HTTPError: If the backend operation fails
        """
        try:
            operation = self.get_led_operation(led_type, state)
            
            if led_type == 'drive':
                if not drive_id:
                    raise ValueError("Drive ID required for drive LED operation")
                result = operation(drive_id)
            else:
                result = operation()
                
            return {'status': result, 'state': state}
        except HTTPError as e:
            self.log.error(f"Failed to set {led_type} LED to {state}: {e}")
            raise

    def handle_get_request(self, led_type: str, 
                          drive_id: Optional[str] = None) -> Dict[str, Any]:
        """Handle a GET request for LED status.
        
        Args:
            led_type: Type of LED ('chassis' or 'drive')
            drive_id: Optional drive identifier
            
        Returns:
            LED status information
        """
        self.validate_led_type(led_type)
        
        if led_type == 'drive':
            self.validate_drive_id(drive_id)
            
        return self.get_led_status(led_type, drive_id)

    def handle_patch_request(self, led_type: str, state: str,
                            drive_id: Optional[str] = None) -> Dict[str, Any]:
        """Handle a PATCH request to change LED state.
        
        Args:
            led_type: Type of LED ('chassis' or 'drive')
            state: Desired LED state ('on' or 'off')
            drive_id: Optional drive identifier
            
        Returns:
            Operation result
        """
        self.validate_led_type(led_type)
        self.validate_led_state(state)
        
        if led_type == 'drive':
            self.validate_drive_id(drive_id)
            
        return self.set_led_state(led_type, state, drive_id)
