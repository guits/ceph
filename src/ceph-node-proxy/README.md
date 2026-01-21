# Ceph Node Proxy

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

A proxy service to monitor Ceph node hardware via out-of-band (OOB) management APIs such as Redfish.

## 📋 Description

Ceph Node Proxy is a daemon that:
- Connects to out-of-band management controllers (iDRAC, iLO, etc.)
- Collects hardware data (CPU, memory, disks, fans, etc.)
- Exposes a REST API to query and control hardware
- Reports changes to the Ceph manager

## 🚀 Quick Installation

```bash
# Clone the project
cd /path/to/ceph-node-proxy

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .

# Copy and edit configuration
cp node-proxy.yml.example /etc/ceph/node-proxy.yml
vi /etc/ceph/node-proxy.yml

# Start the service
python -m ceph_node_proxy.main --config /path/to/config.json
```

## 🏗️ Architecture

The project follows a modular layered architecture:

```
┌─────────────────┐
│   REST API      │  CherryPy endpoints
├─────────────────┤
│   Manager       │  Orchestration
├─────────────────┤
│ System/Reporter │  Data collection & reporting
├─────────────────┤
│   Client        │  Redfish HTTP client
└─────────────────┘
```

**For more details, consult [ARCHITECTURE.md](ARCHITECTURE.md)**

## 📦 Components

### Core
- **main.py**: Entry point and orchestration (NodeProxyManager)
- **config.py**: Structured configuration management
- **util.py**: Utilities (logging, HTTP, threads)

### System Layer
- **basesystem.py**: Abstract interface for system backends
- **baseredfishsystem.py**: Generic Redfish implementation
- **redfishdellsystem.py**: Dell iDRAC specifics

### Client Layer
- **baseclient.py**: Abstract interface for clients
- **redfish_client.py**: Redfish HTTP client

### API Layer
- **api.py**: CherryPy REST endpoints
- **api_server.py**: Server configuration and lifecycle
- **led_handler.py**: LED management (chassis/drive)

### Reporter
- **reporter.py**: Periodic data sending to manager

## 🔧 Configuration

The YAML configuration file controls all aspects of the service:

```yaml
# /etc/ceph/node-proxy.yml
reporter:
  check_interval: 5
  push_data_max_retries: 30
  endpoint: '/node-proxy/data'
  scheme: 'https'

system:
  refresh_interval: 5

api:
  port: 9456
  host: '0.0.0.0'

logging:
  level: 20  # INFO
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
```

See [node-proxy.yml.example](node-proxy.yml.example) for a complete example.

## 🔌 REST API

### Public Endpoints (GET)

| Endpoint | Description |
|----------|-------------|
| `/memory` | RAM memory state |
| `/processors` | Processor state |
| `/storage` | Disk state |
| `/network` | Network interface state |
| `/power` | Power supply state |
| `/fans` | Fan state |
| `/firmwares` | Firmware versions |
| `/led/{type}/{id}` | LED state (chassis or drive) |

### Protected Endpoints (authentication required)

| Endpoint | Method | Description |
|----------|---------|-------------|
| `/shutdown` | POST | Shutdown physical server |
| `/powercycle` | POST | Reboot server |
| `/led/{type}/{id}` | PATCH | Control LEDs |

### Examples

```bash
# Get memory state
curl https://node:9456/memory

# Turn on disk LED (auth required)
curl -X PATCH https://node:9456/led/drive/disk01 \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"state": "on"}'

# Turn off chassis LED
curl -X PATCH https://node:9456/led/chassis \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"state": "off"}'
```

## 🧪 Testing

Example tests are provided to demonstrate testability:

```bash
# Run unit tests
python tests_example.py

# With verbose output
python tests_example.py -v
```

Tests demonstrate:
- ✅ Dependency injection facilitating mocking
- ✅ Isolated tests of each component
- ✅ Business logic validation

**See [tests_example.py](tests_example.py) for complete examples**

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Detailed system architecture |
| [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md) | Architectural improvements summary |
| [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) | Migration guide from old version |

## 🎯 Features

### ✅ Hardware Monitoring
- Processors (model, cores, threads, status)
- Memory (capacity, type, status)
- Storage (disks, capacity, protocol, location)
- Network (interfaces, speed, status)
- Power (PSU status, model)
- Fans (status, context)
- Firmwares (versions, updateable)

### ✅ Control
- Server shutdown (graceful or forced)
- Power cycle
- Identification LED control (chassis and disks)

### ✅ Reporting
- Automatic sending to Ceph manager
- CephX authentication
- Diff-based (sends only changes)

## 🔐 Security

### Authentication
- **REST API**: HTTP Basic Auth (OOB credentials)
- **Redfish**: Session-based with X-Auth-Token
- **Ceph Manager**: CephX (name + secret)

### Transport
- **HTTPS** mandatory everywhere
- **SSL certificates** provided by Ceph
- **CA validation** for manager communications

## 🛠️ Development

### Prerequisites
- Python 3.9+
- CherryPy
- PyYAML
- Access to a server with Redfish (Dell iDRAC, HPE iLO, etc.)

### Project Structure

```
ceph_node_proxy/
├── __init__.py
├── config.py           # Configuration management
├── main.py             # Entry point & orchestration
├── api.py              # REST API endpoints
├── api_server.py       # CherryPy server lifecycle
├── led_handler.py      # LED control logic
├── reporter.py         # Data reporting to Ceph
├── basesystem.py       # System interface
├── baseredfishsystem.py  # Redfish implementation
├── redfishdellsystem.py  # Dell-specific
├── baseclient.py       # Client interface
├── redfish_client.py   # Redfish HTTP client
└── util.py             # Utilities
```

### Adding a New Backend

To support a new type of OOB controller:

1. Create a client: inherit from `BaseClient`
2. Create a system: inherit from `BaseSystem` or `BaseRedfishSystem`
3. Implement abstract methods
4. Use in `main.py`

**Example for HPE iLO:**

```python
# iloclient.py
class IloClient(BaseClient):
    def login(self) -> None:
        # iLO implementation
        pass

# ilosystem.py
class IloSystem(BaseRedfishSystem):
    def _update_memory(self) -> None:
        # iLO-specific logic
        pass
```

### Development Principles

- ✅ **Dependency injection**: facilitates testing
- ✅ **Separation of responsibilities**: one class = one responsibility
- ✅ **Clear interface**: documented public methods
- ✅ **Type hints**: Python typing for better maintainability
- ✅ **Docstrings**: documentation of all public APIs

## 📊 Metrics

### Typical Performance
- **Data collection**: ~5 seconds per cycle
- **Reporting**: ~5 seconds between checks
- **API response time**: <50ms (cache read)

### Threads
- **Main**: Component monitoring (every 20s)
- **System**: Redfish data collection (every 5s)
- **Reporter**: Push to manager (every 5s if changed)
- **API**: CherryPy HTTP server

## 🐛 Troubleshooting

### Enable Debug Logs

```bash
python -m ceph_node_proxy.main --config /path/to/config.json --debug
```

### Common Issues

**"Can't initialize the redfish system"**
- Check OOB credentials
- Check network connectivity to iDRAC/iLO
- Verify Redfish is enabled

**"No oob details could be loaded"**
- Check connectivity to Ceph manager
- Check CephX credentials
- Check CA certificate

**"API server error"**
- Check port is not already in use
- Check SSL certificates
- Check permissions

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

### Guidelines

- Follow Python code conventions (PEP 8)
- Add docstrings for all public functions
- Add tests for new features
- Update documentation if necessary

## 📝 License

This project is part of Ceph and follows the same license.

## 🔗 Useful Links

- [Ceph Documentation](https://docs.ceph.com/)
- [Redfish Specification](https://www.dmtf.org/standards/redfish)
- [CherryPy Documentation](https://docs.cherrypy.dev/)

## 📮 Support

For help:
- Consult [ARCHITECTURE.md](ARCHITECTURE.md) to understand how it works
- Consult [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for migration questions
- Open an issue on the Ceph tracker

---

**Ceph Node Proxy** - Hardware monitoring for Ceph via Redfish
