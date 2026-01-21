"""Configuration management for ceph-node-proxy.

This module provides configuration classes and default values for the proxy service.
"""
import logging
import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class ReporterConfig:
    """Configuration for the Reporter component."""
    check_interval: int = 5
    push_data_max_retries: int = 30
    endpoint: str = '/node-proxy/data'
    scheme: str = 'https'


@dataclass
class SystemConfig:
    """Configuration for the System component."""
    refresh_interval: int = 5


@dataclass
class ApiConfig:
    """Configuration for the API component."""
    port: int = 9456
    host: str = '0.0.0.0'


@dataclass
class LoggingConfig:
    """Configuration for logging."""
    level: int = logging.INFO
    format: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


@dataclass
class AppConfig:
    """Main application configuration."""
    reporter: ReporterConfig = field(default_factory=ReporterConfig)
    system: SystemConfig = field(default_factory=SystemConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'AppConfig':
        """Create AppConfig from a dictionary.
        
        Args:
            config_dict: Dictionary containing configuration values
            
        Returns:
            AppConfig instance
        """
        reporter_data = config_dict.get('reporter', {})
        system_data = config_dict.get('system', {})
        api_data = config_dict.get('api', {})
        logging_data = config_dict.get('logging', {})

        return cls(
            reporter=ReporterConfig(**reporter_data),
            system=SystemConfig(**system_data),
            api=ApiConfig(**api_data),
            logging=LoggingConfig(**logging_data)
        )

    @classmethod
    def from_file(cls, config_file: str) -> 'AppConfig':
        """Load configuration from a YAML file.
        
        Args:
            config_file: Path to the YAML configuration file
            
        Returns:
            AppConfig instance with values from file or defaults
        """
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config_dict = yaml.safe_load(f) or {}
            return cls.from_dict(config_dict)
        return cls()

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of the configuration
        """
        return {
            'reporter': {
                'check_interval': self.reporter.check_interval,
                'push_data_max_retries': self.reporter.push_data_max_retries,
                'endpoint': self.reporter.endpoint,
                'scheme': self.reporter.scheme,
            },
            'system': {
                'refresh_interval': self.system.refresh_interval,
            },
            'api': {
                'port': self.api.port,
                'host': self.api.host,
            },
            'logging': {
                'level': self.logging.level,
                'format': self.logging.format,
            }
        }


class ConfigManager:
    """Manager for application configuration with reload capability."""

    def __init__(self, config_file: Optional[str] = None):
        """Initialize the configuration manager.
        
        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file or '/etc/ceph/node-proxy.yml'
        self._config: AppConfig = AppConfig.from_file(self.config_file)

    @property
    def config(self) -> AppConfig:
        """Get the current configuration.
        
        Returns:
            Current AppConfig instance
        """
        return self._config

    def reload(self, config_file: Optional[str] = None) -> None:
        """Reload configuration from file.
        
        Args:
            config_file: Optional new path to configuration file
        """
        if config_file:
            self.config_file = config_file
        self._config = AppConfig.from_file(self.config_file)

    def __getitem__(self, key: str) -> Any:
        """Support dictionary-style access for backward compatibility.
        
        Args:
            key: Configuration key
            
        Returns:
            Configuration value
        """
        return getattr(self._config, key)
