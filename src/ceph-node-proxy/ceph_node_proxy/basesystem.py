import socket
from threading import Lock
from ceph_node_proxy.util import get_logger, BaseThread
from ceph_node_proxy.config import ConfigManager
from typing import Dict, Any
from ceph_node_proxy.baseclient import BaseClient


class BaseSystem(BaseThread):
    """Base class for system hardware monitoring backends.
    
    This class provides the interface for hardware monitoring operations
    and defines the contract that concrete implementations must follow.
    """

    def __init__(self, **kw: Any) -> None:
        """Initialize the base system.
        
        Args:
            **kw: Keyword arguments including optional config
        """
        super().__init__()
        self.lock: Lock = Lock()
        self._system: Dict = {}
        self.config: ConfigManager = kw.get('config')
        self.client: BaseClient
        self.log = get_logger(__name__)

    def main(self) -> None:
        raise NotImplementedError()

    def get_system(self) -> Dict[str, Any]:
        raise NotImplementedError()

    def get_status(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_metadata(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_processors(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_memory(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_fans(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_power(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_network(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_storage(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_firmwares(self) -> Dict[str, Dict[str, Dict]]:
        raise NotImplementedError()

    def get_sn(self) -> str:
        raise NotImplementedError()

    def get_led(self) -> Dict[str, Any]:
        raise NotImplementedError()

    def set_led(self, data: Dict[str, str]) -> int:
        raise NotImplementedError()

    def get_chassis_led(self) -> Dict[str, Any]:
        raise NotImplementedError()

    def set_chassis_led(self, data: Dict[str, str]) -> int:
        raise NotImplementedError()

    def device_led_on(self, device: str) -> int:
        raise NotImplementedError()

    def device_led_off(self, device: str) -> int:
        raise NotImplementedError()

    def get_device_led(self, device: str) -> Dict[str, Any]:
        raise NotImplementedError()

    def set_device_led(self, device: str, data: Dict[str, bool]) -> int:
        raise NotImplementedError()

    def chassis_led_on(self) -> int:
        raise NotImplementedError()

    def chassis_led_off(self) -> int:
        raise NotImplementedError()

    def get_host(self) -> str:
        """Get the hostname of the system.
        
        Returns:
            System hostname
        """
        return socket.gethostname()

    def request_shutdown(self) -> None:
        """Request graceful shutdown of the system backend."""
        self.pending_shutdown = True

    def logout(self) -> None:
        """Logout from the backend client connection."""
        if hasattr(self, 'client') and self.client:
            self.client.logout()

    def stop_update_loop(self) -> None:
        """Stop the update loop."""
        raise NotImplementedError()

    def flush(self) -> None:
        """Flush cached system data."""
        raise NotImplementedError()

    def shutdown_host(self, force: bool = False) -> int:
        """Shutdown the physical host.
        
        Args:
            force: Whether to force shutdown
            
        Returns:
            HTTP status code
        """
        raise NotImplementedError()

    def powercycle(self) -> int:
        """Power cycle the physical host.
        
        Returns:
            HTTP status code
        """
        raise NotImplementedError()
