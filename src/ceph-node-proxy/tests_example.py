"""Example unit tests demonstrating the improved testability after refactoring.

These tests show how dependency injection makes the code much easier to test.
"""
import unittest
from unittest.mock import Mock, MagicMock, patch
from ceph_node_proxy.api import NodeProxyApi
from ceph_node_proxy.led_handler import LedHandler
from ceph_node_proxy.config import ConfigManager, AppConfig, ApiConfig


class TestNodeProxyApiWithDependencyInjection(unittest.TestCase):
    """Tests demonstrating how dependency injection enables easy testing."""

    def setUp(self):
        """Set up mocks for all dependencies."""
        # Mock all dependencies
        self.mock_system = Mock()
        self.mock_reporter = Mock()
        self.mock_config = Mock(spec=ConfigManager)
        self.mock_config.config = Mock(spec=AppConfig)
        self.mock_config.config.api = Mock(spec=ApiConfig)
        self.mock_config.config.api.port = 9456
        
        # Create API instance with mocked dependencies
        self.api = NodeProxyApi(
            system=self.mock_system,
            reporter=self.mock_reporter,
            config=self.mock_config,
            username='test_user',
            password='test_pass',
            ssl_crt='fake_cert',
            ssl_key='fake_key'
        )

    def test_check_auth_valid_credentials(self):
        """Test authentication with valid credentials."""
        result = self.api.check_auth('realm', 'test_user', 'test_pass')
        self.assertTrue(result)

    def test_check_auth_invalid_credentials(self):
        """Test authentication with invalid credentials."""
        result = self.api.check_auth('realm', 'wrong_user', 'wrong_pass')
        self.assertFalse(result)

    def test_api_has_correct_port(self):
        """Test that API uses the configured port."""
        self.assertEqual(self.api.socket_port, 9456)


class TestLedHandlerIsolated(unittest.TestCase):
    """Tests for LED handler with mocked backend."""

    def setUp(self):
        """Set up LED handler with mocked backend."""
        self.mock_backend = Mock()
        self.led_handler = LedHandler(self.mock_backend)

    def test_validate_led_type_chassis_valid(self):
        """Test validation of valid chassis LED type."""
        # Should not raise
        try:
            self.led_handler.validate_led_type('chassis')
        except ValueError:
            self.fail("validate_led_type raised ValueError unexpectedly")

    def test_validate_led_type_drive_valid(self):
        """Test validation of valid drive LED type."""
        # Should not raise
        try:
            self.led_handler.validate_led_type('drive')
        except ValueError:
            self.fail("validate_led_type raised ValueError unexpectedly")

    def test_validate_led_type_invalid(self):
        """Test validation of invalid LED type."""
        with self.assertRaises(ValueError) as context:
            self.led_handler.validate_led_type('invalid')
        self.assertIn("chassis", str(context.exception).lower())

    def test_validate_led_type_none(self):
        """Test validation with None LED type."""
        with self.assertRaises(ValueError):
            self.led_handler.validate_led_type(None)

    def test_validate_drive_id_valid(self):
        """Test validation of valid drive ID."""
        self.mock_backend.get_storage.return_value = {'disk01': {}, 'disk02': {}}
        
        # Should not raise
        try:
            self.led_handler.validate_drive_id('disk01')
        except ValueError:
            self.fail("validate_drive_id raised ValueError unexpectedly")

    def test_validate_drive_id_not_found(self):
        """Test validation of non-existent drive ID."""
        self.mock_backend.get_storage.return_value = {'disk01': {}}
        
        with self.assertRaises(ValueError) as context:
            self.led_handler.validate_drive_id('disk99')
        self.assertIn("not found", str(context.exception).lower())

    def test_validate_led_state_on(self):
        """Test validation of 'on' state."""
        try:
            self.led_handler.validate_led_state('on')
        except ValueError:
            self.fail("validate_led_state raised ValueError unexpectedly")

    def test_validate_led_state_off(self):
        """Test validation of 'off' state."""
        try:
            self.led_handler.validate_led_state('off')
        except ValueError:
            self.fail("validate_led_state raised ValueError unexpectedly")

    def test_validate_led_state_invalid(self):
        """Test validation of invalid state."""
        with self.assertRaises(ValueError) as context:
            self.led_handler.validate_led_state('blink')
        self.assertIn("on|off", str(context.exception).lower())

    def test_get_led_operation_drive_on(self):
        """Test getting correct operation for turning drive LED on."""
        operation = self.led_handler.get_led_operation('drive', 'on')
        self.assertEqual(operation, self.mock_backend.device_led_on)

    def test_get_led_operation_drive_off(self):
        """Test getting correct operation for turning drive LED off."""
        operation = self.led_handler.get_led_operation('drive', 'off')
        self.assertEqual(operation, self.mock_backend.device_led_off)

    def test_get_led_operation_chassis_on(self):
        """Test getting correct operation for turning chassis LED on."""
        operation = self.led_handler.get_led_operation('chassis', 'on')
        self.assertEqual(operation, self.mock_backend.chassis_led_on)

    def test_get_led_operation_chassis_off(self):
        """Test getting correct operation for turning chassis LED off."""
        operation = self.led_handler.get_led_operation('chassis', 'off')
        self.assertEqual(operation, self.mock_backend.chassis_led_off)

    def test_get_led_status_chassis(self):
        """Test getting chassis LED status."""
        expected_status = {'LocationIndicatorActive': True, 'http_code': 200}
        self.mock_backend.get_chassis_led.return_value = expected_status
        
        result = self.led_handler.get_led_status('chassis')
        
        self.mock_backend.get_chassis_led.assert_called_once()
        self.assertEqual(result, expected_status)

    def test_get_led_status_drive(self):
        """Test getting drive LED status."""
        expected_status = {'LocationIndicatorActive': False, 'http_code': 200}
        self.mock_backend.get_device_led.return_value = expected_status
        
        result = self.led_handler.get_led_status('drive', 'disk01')
        
        self.mock_backend.get_device_led.assert_called_once_with('disk01')
        self.assertEqual(result, expected_status)

    def test_set_led_state_chassis_on(self):
        """Test setting chassis LED to on."""
        self.mock_backend.chassis_led_on.return_value = 200
        
        result = self.led_handler.set_led_state('chassis', 'on')
        
        self.mock_backend.chassis_led_on.assert_called_once()
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['state'], 'on')

    def test_set_led_state_drive_off(self):
        """Test setting drive LED to off."""
        self.mock_backend.device_led_off.return_value = 200
        
        result = self.led_handler.set_led_state('drive', 'off', 'disk01')
        
        self.mock_backend.device_led_off.assert_called_once_with('disk01')
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['state'], 'off')

    def test_handle_get_request_chassis(self):
        """Test handling GET request for chassis LED."""
        expected_status = {'LocationIndicatorActive': True}
        self.mock_backend.get_chassis_led.return_value = expected_status
        
        result = self.led_handler.handle_get_request('chassis')
        
        self.assertEqual(result, expected_status)

    def test_handle_get_request_drive(self):
        """Test handling GET request for drive LED."""
        self.mock_backend.get_storage.return_value = {'disk01': {}}
        expected_status = {'LocationIndicatorActive': False}
        self.mock_backend.get_device_led.return_value = expected_status
        
        result = self.led_handler.handle_get_request('drive', 'disk01')
        
        self.assertEqual(result, expected_status)

    def test_handle_patch_request_chassis(self):
        """Test handling PATCH request for chassis LED."""
        self.mock_backend.chassis_led_on.return_value = 200
        
        result = self.led_handler.handle_patch_request('chassis', 'on')
        
        self.assertEqual(result['state'], 'on')
        self.assertEqual(result['status'], 200)


class TestConfigManager(unittest.TestCase):
    """Tests for configuration management."""

    def test_default_config_values(self):
        """Test that default configuration values are set correctly."""
        config = AppConfig()
        
        self.assertEqual(config.api.port, 9456)
        self.assertEqual(config.api.host, '0.0.0.0')
        self.assertEqual(config.reporter.check_interval, 5)
        self.assertEqual(config.system.refresh_interval, 5)

    def test_config_from_dict(self):
        """Test creating configuration from dictionary."""
        config_dict = {
            'api': {'port': 8080, 'host': '127.0.0.1'},
            'reporter': {'check_interval': 10},
        }
        
        config = AppConfig.from_dict(config_dict)
        
        self.assertEqual(config.api.port, 8080)
        self.assertEqual(config.api.host, '127.0.0.1')
        self.assertEqual(config.reporter.check_interval, 10)

    @patch('os.path.exists')
    def test_config_from_nonexistent_file(self, mock_exists):
        """Test loading config from non-existent file returns defaults."""
        mock_exists.return_value = False
        
        config = AppConfig.from_file('/nonexistent/config.yml')
        
        # Should return default values
        self.assertEqual(config.api.port, 9456)

    def test_config_to_dict(self):
        """Test converting configuration to dictionary."""
        config = AppConfig()
        config_dict = config.to_dict()
        
        self.assertIn('api', config_dict)
        self.assertIn('reporter', config_dict)
        self.assertIn('system', config_dict)
        self.assertIn('logging', config_dict)
        self.assertEqual(config_dict['api']['port'], 9456)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
