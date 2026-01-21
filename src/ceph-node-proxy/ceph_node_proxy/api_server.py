"""CherryPy API server configuration and lifecycle management.

This module handles the CherryPy server configuration, SSL setup,
and server lifecycle management.
"""
import cherrypy  # type: ignore
from tempfile import _TemporaryFileWrapper
from typing import Dict, Any, Callable
from ceph_node_proxy.util import get_logger, write_tmp_file


class ApiServerConfig:
    """Handles CherryPy server configuration."""

    def __init__(self, auth_callback: Callable[[str, str, str], bool]):
        """Initialize API server configuration.
        
        Args:
            auth_callback: Function to validate username/password
        """
        self.log = get_logger(__name__)
        self.auth_callback = auth_callback

    def get_cherrypy_config(self) -> Dict[str, Any]:
        """Get the global CherryPy configuration.
        
        Returns:
            Dictionary with CherryPy global configuration
        """
        return {
            'environment': 'production',
            'engine.autoreload.on': False,
            'log.screen': True,
        }

    def get_app_config(self) -> Dict[str, Dict[str, Any]]:
        """Get the application-specific CherryPy configuration.
        
        Returns:
            Dictionary with application configuration
        """
        return {
            '/': {
                'request.methods_with_bodies': ('POST', 'PUT', 'PATCH'),
                'tools.trailing_slash.on': False,
                'tools.auth_basic.realm': 'localhost',
                'tools.auth_basic.checkpassword': self.auth_callback
            }
        }


class SslManager:
    """Manages SSL certificate handling for the API server."""

    def __init__(self):
        """Initialize SSL manager."""
        self.log = get_logger(__name__)
        self.ssl_crt_file: _TemporaryFileWrapper = None
        self.ssl_key_file: _TemporaryFileWrapper = None

    def setup_ssl_files(self, ssl_crt: str, ssl_key: str) -> tuple[str, str]:
        """Create temporary files for SSL certificate and key.
        
        Args:
            ssl_crt: SSL certificate content
            ssl_key: SSL key content
            
        Returns:
            Tuple of (certificate_path, key_path)
        """
        self.log.debug('Creating temporary SSL certificate files')
        self.ssl_crt_file = write_tmp_file(ssl_crt, prefix_name='listener-crt-')
        self.ssl_key_file = write_tmp_file(ssl_key, prefix_name='listener-key-')
        return self.ssl_crt_file.name, self.ssl_key_file.name

    def cleanup(self) -> None:
        """Clean up temporary SSL files."""
        if self.ssl_crt_file:
            self.ssl_crt_file.close()
        if self.ssl_key_file:
            self.ssl_key_file.close()


class ApiServerLifecycle:
    """Manages the lifecycle of the CherryPy API server."""

    def __init__(self, api_instance: Any, ssl_manager: SslManager,
                 config_manager: ApiServerConfig):
        """Initialize server lifecycle manager.
        
        Args:
            api_instance: The API application instance to serve
            ssl_manager: SSL certificate manager
            config_manager: API server configuration manager
        """
        self.log = get_logger(__name__)
        self.api_instance = api_instance
        self.ssl_manager = ssl_manager
        self.config_manager = config_manager

    def configure(self) -> None:
        """Configure CherryPy server."""
        self.log.info('Configuring CherryPy server...')
        cherrypy.config.update(self.config_manager.get_cherrypy_config())

    def mount_application(self) -> None:
        """Mount the API application to CherryPy."""
        self.log.debug('Mounting API application')
        config = self.config_manager.get_app_config()
        cherrypy.tree.mount(self.api_instance, '/', config=config)

    def setup_ssl(self, ssl_crt: str, ssl_key: str) -> None:
        """Setup SSL certificates for the server.
        
        Args:
            ssl_crt: SSL certificate content
            ssl_key: SSL key content
        """
        self.log.debug('Setting up SSL certificates')
        cert_path, key_path = self.ssl_manager.setup_ssl_files(ssl_crt, ssl_key)
        self.api_instance.ssl_certificate = cert_path
        self.api_instance.ssl_private_key = key_path

    def start(self) -> None:
        """Start the CherryPy engine."""
        self.log.info('Starting CherryPy engine...')
        cherrypy.server.unsubscribe()
        cherrypy.engine.start()
        self.log.info('API server started successfully')

    def stop(self) -> None:
        """Stop the CherryPy engine."""
        self.log.info('Stopping CherryPy engine...')
        cherrypy.engine.exit()
        cherrypy.server.httpserver = None
        self.log.info('API server stopped')

    def cleanup(self) -> None:
        """Clean up resources."""
        self.ssl_manager.cleanup()
