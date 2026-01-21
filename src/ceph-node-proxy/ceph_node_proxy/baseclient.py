"""Base client interface for hardware management APIs.

This module defines the base client interface that concrete implementations
(e.g., Redfish) must implement.
"""
from typing import Dict, Any


class BaseClient:
    """Base class for hardware management API clients.
    
    This class defines the interface that all client implementations
    must follow for authentication and data retrieval.
    """

    def __init__(self,
                 host: str,
                 username: str,
                 password: str) -> None:
        """Initialize the base client.
        
        Args:
            host: Hostname or IP address of the management interface
            username: Authentication username
            password: Authentication password
        """
        self.host = host
        self.username = username
        self.password = password

    def login(self) -> None:
        """Authenticate with the management interface.
        
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError()

    def logout(self) -> Dict[str, Any]:
        """Logout from the management interface.
        
        Returns:
            Dictionary with logout response
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError()

    def get_path(self, path: str) -> Dict:
        """Retrieve data from a specific API path.
        
        Args:
            path: API endpoint path
            
        Returns:
            Dictionary with response data
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError()
