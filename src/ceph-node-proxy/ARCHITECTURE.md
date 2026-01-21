# Architecture - Ceph Node Proxy

## Overview

The Ceph Node Proxy is a service that monitors node hardware via out-of-band (OOB) management APIs like Redfish, and reports data to the Ceph manager.

## Layered Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    REST API Layer                       │
│  (CherryPy, HTTP endpoints for query/control)          │
└───────────────────┬─────────────────────────────────────┘
                    │
┌───────────────────┴─────────────────────────────────────┐
│                  Manager Layer                          │
│        (NodeProxyManager - orchestration)               │
└─────────────┬──────────────────┬────────────────────────┘
              │                  │
    ┌─────────┴────────┐  ┌─────┴──────────┐
    │   System Layer   │  │ Reporter Layer │
    │  (Redfish Dell)  │  │ (Data push)    │
    └─────────┬────────┘  └────────────────┘
              │
    ┌─────────┴────────┐
    │   Client Layer   │
    │ (Redfish Client) │
    └──────────────────┘
```

## Main Components

### 1. Configuration Layer (`config.py`)

**Responsibility:** Centralized configuration management

**Main Classes:**
- `AppConfig`: Main configuration (dataclass)
- `ConfigManager`: Manager with reload support

**Data Flow:**
```
YAML File → ConfigManager.from_file() → AppConfig → Components
```

**Example:**
```python
config = ConfigManager('/etc/ceph/node-proxy.yml')
port = config.config.api.port
```

---

### 2. Manager Layer (`main.py`)

**Responsibility:** Component orchestration

**Main Class:** `NodeProxyManager`

**Responsibilities:**
- Component initialization (System, Reporter, API)
- Thread health monitoring
- Lifecycle management
- Shutdown coordination

**Important Public Methods:**
```python
def init_system() -> None
def init_reporter() -> None  
def init_api() -> None
def loop() -> None
def shutdown() -> None
def request_system_shutdown() -> None
def logout_system() -> None
```

**Execution Flow:**
```
main() → NodeProxyManager.run()
         ├─> init_system()
         ├─> init_reporter()
         ├─> init_api()
         └─> loop()  # Monitoring threads
```

---

### 3. System Layer

#### Base (`basesystem.py`)

**Responsibility:** Abstract interface for system backends

**Class:** `BaseSystem(BaseThread)`

**Abstract Methods:**
- `get_system()`: Complete system data
- `get_memory()`: Memory state
- `get_processors()`: Processor state
- `get_storage()`: Storage state
- `get_network()`: Network state
- `get_fans()`: Fan state
- `get_power()`: Power state
- `get_firmwares()`: Firmware versions
- `shutdown_host()`: Server shutdown
- `powercycle()`: Reboot

#### Redfish Base (`baseredfishsystem.py`)

**Responsibility:** Generic Redfish implementation

**Classes:**
- `EndpointMgr`: Redfish endpoint discovery
- `Endpoint`: Endpoint representation
- `BaseRedfishSystem`: Common Redfish logic

**Collection Flow:**
```
BaseRedfishSystem.main()
  └─> Update loop (every 5s)
       ├─> _update_system()
       ├─> _update_sn()
       ├─> _update_memory()
       ├─> _update_processors()
       ├─> _update_storage()
       ├─> _update_network()
       ├─> _update_fans()
       ├─> _update_power()
       └─> _update_firmwares()
```

#### Dell Implementation (`redfishdellsystem.py`)

**Responsibility:** Dell iDRAC specifics

**Class:** `RedfishDellSystem(BaseRedfishSystem)`

**Dell-Specific Additions:**
- Job Service endpoints
- Dell structure parsing
- Dell-specific LED management

---

### 4. Client Layer

#### Base (`baseclient.py`)

**Responsibility:** Abstract client interface

**Class:** `BaseClient`

**Methods:**
- `login()`: Authentication
- `logout()`: Disconnection
- `get_path(path)`: GET request

#### Redfish Client (`redfish_client.py`)

**Responsibility:** Redfish HTTP client

**Class:** `RedFishClient(BaseClient)`

**Features:**
- Session management with X-Auth-Token
- SessionService discovery
- HTTP queries (GET, POST, PATCH, DELETE)
- SSL/TLS support

**Authentication Flow:**
```
login()
  └─> sessionservice_discover()
       └─> query(POST /SessionService/Sessions)
            ├─> Receive X-Auth-Token
            └─> Store session location
```

---

### 5. Reporter Layer (`reporter.py`)

**Responsibility:** Periodic data sending to Ceph manager

**Class:** `Reporter(BaseThread)`

**Reporting Flow:**
```
Reporter.main() loop
  ├─> Wait for system.data_ready
  ├─> Compare with previous_data
  ├─> If changed:
  │    └─> http_req(POST /node-proxy/data)
  └─> Sleep 5s
```

**Data Format:**
```json
{
  "cephx": {
    "name": "client.node-proxy",
    "secret": "AQC..."
  },
  "patch": {
    "host": "node01",
    "sn": "ABC123",
    "status": {...},
    "firmwares": {...}
  }
}
```

---

### 6. API Layer (`api.py`)

**Responsibility:** REST API for querying/controlling the node

**Main Classes:**
- `API(Server)`: CherryPy endpoints
- `NodeProxyApi(Thread)`: Thread managing the server
- `Admin`: Admin endpoints (deprecated)

**Public Endpoints (GET):**
- `/memory`: Memory state
- `/network`: Network state
- `/processors`: Processor state
- `/storage`: Storage state
- `/power`: Power state
- `/fans`: Fan state
- `/firmwares`: Firmware versions
- `/led/{type}/{id}`: LED state

**Protected Endpoints (auth required):**
- `POST /shutdown`: Server shutdown
- `POST /powercycle`: Reboot
- `PATCH /led/{type}/{id}`: LED control

#### API Server Management (`api_server.py`)

**Responsibility:** CherryPy configuration and lifecycle

**Classes:**
- `ApiServerConfig`: CherryPy configuration
- `SslManager`: SSL certificate management
- `ApiServerLifecycle`: Server start/stop

**Responsibility Separation:**
```
NodeProxyApi.run()
  └─> ApiServerLifecycle
       ├─> configure()      # CherryPy config
       ├─> mount_application()  # Mount endpoints
       ├─> setup_ssl()      # SSL certificates
       ├─> start()          # Start engine
       └─> stop()           # Stop engine
```

---

### 7. LED Handler (`led_handler.py`)

**Responsibility:** LED control logic

**Class:** `LedHandler`

**Public Methods:**
- `handle_get_request(type, id?)`: Get state
- `handle_patch_request(type, state, id?)`: Modify state

**Automatic Validation:**
- LED type (chassis/drive)
- State (on/off)
- Drive existence

**Processing Flow:**
```
API._led()
  └─> LedHandler.handle_get/patch_request()
       ├─> validate_led_type()
       ├─> validate_drive_id()  # if drive
       ├─> validate_led_state()  # if PATCH
       └─> Call backend method
```

---

## Design Patterns Used

### 1. Dependency Injection

**Where:** `NodeProxyApi`, `NodeProxyManager`

**Before:**
```python
api = NodeProxyApi(node_proxy_mgr)
api.username = node_proxy_mgr.username  # Tight coupling
```

**After:**
```python
api = NodeProxyApi(system, reporter, config, username, password, ...)
# Explicit dependencies, decoupling
```

### 2. Strategy Pattern

**Where:** `BaseSystem` → `BaseRedfishSystem` → `RedfishDellSystem`

Allows different implementations (Dell, HPE, etc.) with the same interface.

### 3. Template Method

**Where:** `BaseRedfishSystem`

Defines the algorithm skeleton, subclasses implement details:
```python
def main(self):
    while not self.stop:
        self._update_system()      # Implemented
        self._update_sn()          # To implement
        self._update_memory()      # To implement
        # ...
```

### 4. Facade

**Where:** `LedHandler`

Simplifies complex LED management interface:
```python
# Instead of complex logic in API
result = led_handler.handle_patch_request('drive', 'on', 'disk01')
```

### 5. Thread-safe Singleton (Lock)

**Where:** `BaseSystem.lock`

Protection of shared data between threads:
```python
with self.lock:
    self._system = self._get_data()
```

---

## Data Flow

### Startup

```
main()
  │
  ├─> NodeProxyManager.__init__()
  │    ├─> Setup SSL context
  │    ├─> Load ConfigManager
  │    └─> Initialize credentials
  │
  ├─> NodeProxyManager.init()
  │    ├─> init_system()
  │    │    ├─> fetch_oob_details()  # From Ceph mgr
  │    │    └─> RedfishDellSystem.start()
  │    │         └─> RedFishClient.login()
  │    │
  │    ├─> init_reporter()
  │    │    └─> Reporter.start()
  │    │
  │    └─> init_api()
  │         └─> NodeProxyApi.start()
  │              └─> CherryPy engine start
  │
  └─> NodeProxyManager.loop()
       └─> Monitor thread health (every 20s)
```

### Data Collection

```
BaseRedfishSystem (Thread)
  │
  └─> main() loop (every 5s)
       │
       ├─> Acquire lock
       │
       ├─> Query Redfish endpoints
       │    ├─> /Systems/{id}
       │    ├─> /Systems/{id}/Memory
       │    ├─> /Systems/{id}/Processors
       │    ├─> /Systems/{id}/Storage
       │    ├─> /Chassis/{id}/Power
       │    ├─> /Chassis/{id}/Thermal
       │    └─> /UpdateService/FirmwareInventory
       │
       ├─> Parse and store in self._sys
       │
       ├─> Set data_ready = True
       │
       └─> Release lock
```

### Reporting

```
Reporter (Thread)
  │
  └─> main() loop (every 5s)
       │
       ├─> Wait for system.data_ready
       │
       ├─> Acquire system.lock
       │
       ├─> Get system.get_system()
       │
       ├─> Compare with previous_data
       │
       ├─> If changed:
       │    ├─> Build payload with cephx + patch
       │    ├─> POST to mgr /node-proxy/data
       │    └─> Update previous_data
       │
       └─> Release lock
```

### API Request

```
HTTP GET /storage
  │
  ├─> CherryPy routing
  │
  ├─> API.storage()
  │    │
  │    └─> backend.get_storage()
  │         │
  │         ├─> Acquire lock
  │         ├─> Return self._sys['storage']
  │         └─> Release lock
  │
  └─> JSON response
```

---

## Concurrency Management

### Active Threads

1. **Main thread**: NodeProxyManager.loop() - Monitoring
2. **System thread**: BaseRedfishSystem.main() - Data collection
3. **Reporter thread**: Reporter.main() - Data reporting
4. **API thread**: NodeProxyApi.run() - HTTP server

### Synchronization

**Shared Lock**: `BaseSystem.lock`

**Protected by lock:**
- Read/write of `_sys`
- Read/write of `data_ready`
- Redfish queries

**Usage Pattern:**
```python
# Write (System thread)
with self.lock:
    self._sys['memory'] = new_data
    self.data_ready = True

# Read (Reporter/API threads)
with self.lock:
    data = self.get_system()
```

---

## Testing

### Recommended Structure

```
tests/
├── unit/
│   ├── test_config.py
│   ├── test_led_handler.py
│   ├── test_api.py
│   └── test_manager.py
├── integration/
│   ├── test_redfish_flow.py
│   └── test_end_to_end.py
└── fixtures/
    ├── redfish_responses.json
    └── config_examples.yml
```

### Testability

Thanks to dependency injection:

```python
# Mock dependencies
mock_system = Mock()
mock_reporter = Mock()
mock_config = Mock()

# Isolated test
api = NodeProxyApi(mock_system, mock_reporter, mock_config, 'user', 'pass', '', '')
result = api.check_auth('realm', 'user', 'pass')
assert result is True
```

---

## Extensibility

### Adding a New Backend (e.g., HPE iLO)

1. Create `iloclient.py` inheriting from `BaseClient`
2. Create `ilosystem.py` inheriting from `BaseRedfishSystem` (or `BaseSystem`)
3. Implement abstract methods
4. Use in `main.py`:

```python
from ceph_node_proxy.ilosystem import IloSystem

self.system = IloSystem(
    host=oob_details['host'],
    # ...
)
```

### Adding a New API Endpoint

In `api.py`:

```python
@cherrypy.expose
@cherrypy.tools.json_out()
def my_endpoint(self) -> Dict[str, Any]:
    return {'data': self.backend.get_my_data()}
```

---

## Security

### Authentication

- **External API**: Basic Auth (OOB username/password)
- **Redfish**: Session-based (X-Auth-Token)
- **Ceph Manager**: CephX (name + secret)

### SSL/TLS

- **API**: HTTPS with certificates provided by Ceph
- **Redfish**: HTTPS with optional certificate validation
- **Manager**: HTTPS with CA certificate validation

### Secrets

- No hardcoded secrets in code
- Credentials provided via JSON config file (main)
- OOB credentials retrieved from manager

---

## Performance

### Optimizations

1. **Parallel Collection**: ThreadPoolExecutor for Redfish queries
2. **Cache**: Data stored in memory (`_sys`)
3. **Diff Reporting**: Send only if data changed
4. **Configurable Intervals**: system.refresh_interval, reporter.check_interval

### Typical Metrics

- **Data collection**: ~5s per cycle
- **Reporter**: ~5s between checks
- **API response time**: <50ms (cache read)

---

## Troubleshooting

### Logs

Enable debug mode:
```bash
python main.py --config /path/to/config.json --debug
```

### Checkpoints

1. **System thread**: `self.log.debug('Updating memory')`
2. **Reporter**: `self.log.info('sending data to {url}')`
3. **API**: Automatic CherryPy logs

### Common Issues

**System thread crash** → Checked in Manager.loop()
**Lock deadlock** → Always use `with self.lock:`
**Redfish timeout** → Adjust timeout in queries

---

## References

- [Redfish Specification](https://www.dmtf.org/standards/redfish)
- [CherryPy Documentation](https://docs.cherrypy.dev/)
- [Python Threading](https://docs.python.org/3/library/threading.html)
