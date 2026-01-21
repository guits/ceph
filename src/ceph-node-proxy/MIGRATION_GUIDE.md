# Migration Guide - Ceph Node Proxy

## Introduction

This guide helps you migrate to the new architecture of the `ceph-node-proxy` project after the major refactoring.

## Important Changes

### 1. Configuration

#### Old Method (deprecated)
```python
from ceph_node_proxy.util import Config, CONFIG

config = Config('/etc/ceph/node-proxy.yml', config=CONFIG)
port = config.__dict__['api']['port']
```

#### New Method
```python
from ceph_node_proxy.config import ConfigManager

config = ConfigManager('/etc/ceph/node-proxy.yml')
port = config.config.api.port  # Type-safe and autocomplete
```

#### Accessing Different Sections

```python
# API configuration
host = config.config.api.host
port = config.config.api.port

# Reporter configuration
check_interval = config.config.reporter.check_interval
scheme = config.config.reporter.scheme

# Logging configuration
log_level = config.config.logging.level
log_format = config.config.logging.format

# System configuration
refresh_interval = config.config.system.refresh_interval
```

#### Configuration Reload

```python
# Reload from the same file
config.reload()

# Reload from a new file
config.reload('/path/to/new/config.yml')
```

---

### 2. NodeProxyApi Instantiation

#### Old Method (deprecated)
```python
from ceph_node_proxy.api import NodeProxyApi

api = NodeProxyApi(node_proxy_mgr)
```

#### New Method
```python
from ceph_node_proxy.api import NodeProxyApi

api = NodeProxyApi(
    system=system_instance,
    reporter=reporter_instance,
    config=config_manager,
    username='admin',
    password='secret',
    ssl_crt=cert_content,
    ssl_key=key_content
)
```

**Why this change?**
- Explicit dependency injection
- Easier to test (mock dependencies)
- Reduced coupling
- Clear and documented dependencies

---

### 3. LED Management

#### Old Method (internal)
LEDs were managed directly in the `API` class with complex logic.

#### New Method
Logic is now in a dedicated handler:

```python
from ceph_node_proxy.led_handler import LedHandler

led_handler = LedHandler(backend)

# GET status
status = led_handler.handle_get_request(led_type='chassis')
status = led_handler.handle_get_request(led_type='drive', drive_id='disk01')

# PATCH state
result = led_handler.handle_patch_request(
    led_type='chassis',
    state='on'
)
result = led_handler.handle_patch_request(
    led_type='drive',
    state='off',
    drive_id='disk01'
)
```

**Automatic Validation:**
The handler automatically validates:
- LED type (chassis/drive)
- State (on/off)
- Drive ID existence

---

### 4. System Encapsulation

#### Old Method (encapsulation violation)
```python
# Direct access to internal attributes
node_proxy_mgr.system.pending_shutdown = True
node_proxy_mgr.system.client.logout()
```

#### New Method (respected encapsulation)
```python
# Use public interface
node_proxy_mgr.request_system_shutdown()
node_proxy_mgr.logout_system()
```

**New Public Methods:**

In `NodeProxyManager`:
```python
def request_system_shutdown(self) -> None:
    """Request graceful shutdown of the system backend"""

def logout_system(self) -> None:
    """Logout from the system backend"""
```

In `BaseSystem`:
```python
def request_shutdown(self) -> None:
    """Request graceful shutdown"""

def logout(self) -> None:
    """Logout from the backend client"""
```

---

### 5. Logging

#### Old Method
```python
from ceph_node_proxy.util import get_logger, CONFIG

logger = get_logger(__name__)
# Global level defined in CONFIG
```

#### New Method
```python
from ceph_node_proxy.util import get_logger

# With default level
logger = get_logger(__name__)

# With custom level
logger = get_logger(__name__, level=logging.DEBUG)

# With custom format
logger = get_logger(__name__, 
                   level=logging.INFO,
                   log_format='%(levelname)s: %(message)s')
```

---

## Complete Migration Example

### Before

```python
from ceph_node_proxy.main import NodeProxyManager
from ceph_node_proxy.util import CONFIG

# Configuration mixed with code
node_proxy_mgr = NodeProxyManager(**{
    'mgr_host': '192.168.1.1',
    'cephx_name': 'client.node-proxy',
    'cephx_secret': 'AQC...',
    'ca_path': '/tmp/ca.pem',
    'api_ssl_crt': cert_content,
    'api_ssl_key': key_content,
    'mgr_agent_port': '8765'
})

# Direct access to internal attributes
node_proxy_mgr.system.pending_shutdown = True
```

### After

```python
from ceph_node_proxy.main import NodeProxyManager
from ceph_node_proxy.config import ConfigManager

# Separated configuration
config = ConfigManager('/etc/ceph/node-proxy.yml')

# Explicit dependency injection
node_proxy_mgr = NodeProxyManager(
    mgr_host='192.168.1.1',
    cephx_name='client.node-proxy',
    cephx_secret='AQC...',
    ca_path='/tmp/ca.pem',
    api_ssl_crt=cert_content,
    api_ssl_key=key_content,
    mgr_agent_port='8765',
    config_file='/etc/ceph/node-proxy.yml'
)

# Respected public interface
node_proxy_mgr.request_system_shutdown()
```

---

## Testing

### Before (difficult to test)
```python
# Impossible to mock easily due to hidden dependencies
api = NodeProxyApi(node_proxy_mgr)
```

### After (easy to test)
```python
from unittest.mock import Mock

# Mock injection
mock_system = Mock()
mock_reporter = Mock()
mock_config = Mock()

api = NodeProxyApi(
    system=mock_system,
    reporter=mock_reporter,
    config=mock_config,
    username='test',
    password='test',
    ssl_crt='',
    ssl_key=''
)

# Isolated test
mock_system.get_storage.return_value = {'disk01': {}}
result = api.led_handler.handle_get_request('drive', 'disk01')
```

---

## YAML Configuration File

Example structure of `/etc/ceph/node-proxy.yml` file:

```yaml
# Reporter configuration
reporter:
  check_interval: 5
  push_data_max_retries: 30
  endpoint: '/node-proxy/data'
  scheme: 'https'

# System configuration
system:
  refresh_interval: 5

# API configuration
api:
  port: 9456
  host: '0.0.0.0'

# Logging configuration
logging:
  level: 20  # INFO=20, DEBUG=10, WARNING=30
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
```

---

## Migration Checklist

- [ ] Replace `Config` with `ConfigManager`
- [ ] Update configuration access (use `config.config.section.key`)
- [ ] Update `NodeProxyApi` instantiation with dependency injection
- [ ] Replace direct internal attribute access with public methods
- [ ] Update imports (new modules `config`, `api_server`, `led_handler`)
- [ ] Verify YAML configuration file exists and is valid
- [ ] Test main functionalities
- [ ] Update unit tests to use dependency injection

---

## Troubleshooting

### Error: `AttributeError: 'ConfigManager' object has no attribute '__dict__'`

**Cause:** Attempting to access configuration with old syntax

```python
# ❌ Old
port = config.__dict__['api']['port']

# ✅ New
port = config.config.api.port
```

---

### Error: `TypeError: NodeProxyApi.__init__() got an unexpected keyword argument 'node_proxy_mgr'`

**Cause:** Using old signature

```python
# ❌ Old
api = NodeProxyApi(node_proxy_mgr)

# ✅ New
api = NodeProxyApi(system, reporter, config, username, password, ssl_crt, ssl_key)
```

---

### Error: `ModuleNotFoundError: No module named 'ceph_node_proxy.config'`

**Cause:** New files are not installed

**Solution:**
```bash
cd /path/to/ceph-node-proxy
pip install -e .
```

---

## Support

For any migration questions or issues, consult:
- `REFACTORING_SUMMARY.md` to understand changes
- Docstrings in the code for API documentation
- Unit tests as usage examples

---

## Backward Compatibility

**Warning:** This version contains non-backward-compatible changes.

If you have existing code using the old API, follow this guide to update it. Old methods are no longer supported.

**Minimum Python version required:** 3.9+ (for advanced type hints)
