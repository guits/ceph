import cherrypy  # type: ignore
from urllib.error import HTTPError
from cherrypy._cpserver import Server  # type: ignore
from threading import Thread, Event
from typing import Dict, Any, List, TYPE_CHECKING, Optional
from ceph_node_proxy.util import get_logger
from ceph_node_proxy.basesystem import BaseSystem
from ceph_node_proxy.reporter import Reporter
from ceph_node_proxy.config import ConfigManager
from ceph_node_proxy.led_handler import LedHandler
from ceph_node_proxy.api_server import ApiServerConfig, SslManager, ApiServerLifecycle

if TYPE_CHECKING:
    from ceph_node_proxy.main import NodeProxyManager


@cherrypy.tools.auth_basic(on=True)
@cherrypy.tools.allow(methods=['PUT'])
@cherrypy.tools.json_out()
class Admin():
    def __init__(self, api: 'API') -> None:
        self.api = api

    @cherrypy.expose
    def start(self) -> Dict[str, str]:
        self.api.backend.start()
        self.api.reporter.run()
        return {'ok': 'node-proxy daemon started'}

    @cherrypy.expose
    def reload(self) -> Dict[str, str]:
        self.api.config.reload()
        return {'ok': 'node-proxy config reloaded'}

    def _stop(self) -> None:
        self.api.backend.shutdown()
        self.api.reporter.shutdown()

    @cherrypy.expose
    def stop(self) -> Dict[str, str]:
        self._stop()
        return {'ok': 'node-proxy daemon stopped'}

    @cherrypy.expose
    def shutdown(self) -> Dict[str, str]:
        self._stop()
        cherrypy.engine.exit()
        return {'ok': 'Server shutdown.'}

    @cherrypy.expose
    def flush(self) -> Dict[str, str]:
        self.api.backend.flush()
        return {'ok': 'node-proxy data flushed'}


class API(Server):
    """Main API class exposing hardware monitoring endpoints."""

    def __init__(self,
                 backend: 'BaseSystem',
                 reporter: 'Reporter',
                 config: 'ConfigManager',
                 addr: str = '0.0.0.0',
                 port: int = 0) -> None:
        """Initialize the API server.
        
        Args:
            backend: System backend for hardware operations
            reporter: Reporter instance for data reporting
            config: Configuration manager
            addr: Address to bind to
            port: Port to bind to (0 = use config)
        """
        super().__init__()
        self.log = get_logger(__name__)
        self.backend = backend
        self.reporter = reporter
        self.config = config
        self.led_handler = LedHandler(backend)
        self.socket_port = self.config.config.api.port if not port else port
        self.socket_host = addr
        self.subscribe()

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def memory(self) -> Dict[str, Any]:
        return {'memory': self.backend.get_memory()}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def network(self) -> Dict[str, Any]:
        return {'network': self.backend.get_network()}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def processors(self) -> Dict[str, Any]:
        return {'processors': self.backend.get_processors()}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def storage(self) -> Dict[str, Any]:
        return {'storage': self.backend.get_storage()}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def power(self) -> Dict[str, Any]:
        return {'power': self.backend.get_power()}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def fans(self) -> Dict[str, Any]:
        return {'fans': self.backend.get_fans()}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def firmwares(self) -> Dict[str, Any]:
        return {'firmwares': self.backend.get_firmwares()}

    def _cp_dispatch(self, vpath: List[str]) -> 'API':
        if vpath[0] == 'led' and len(vpath) > 1:  # /led/{type}/{id}
            _type = vpath[1]
            cherrypy.request.params['type'] = _type
            vpath.pop(1)  # /led/{id} or # /led
            if _type == 'drive' and len(vpath) > 1:  # /led/{id}
                _id = vpath[1]
                vpath.pop(1)  # /led
                cherrypy.request.params['id'] = _id
            vpath[0] = '_led'
        # /<endpoint>
        return self

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST'])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.tools.auth_basic(on=True)
    def shutdown(self, **kw: Any) -> int:
        data: Dict[str, bool] = cherrypy.request.json

        if 'force' not in data.keys():
            msg = "The key 'force' wasn't passed."
            self.log.debug(msg)
            raise cherrypy.HTTPError(400, msg)
        try:
            result: int = self.backend.shutdown_host(force=data['force'])
        except HTTPError as e:
            raise cherrypy.HTTPError(e.code, e.reason)
        return result

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST'])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.tools.auth_basic(on=True)
    def powercycle(self, **kw: Any) -> int:
        try:
            result: int = self.backend.powercycle()
        except HTTPError as e:
            raise cherrypy.HTTPError(e.code, e.reason)
        return result

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET', 'PATCH'])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.tools.auth_basic(on=True)
    def _led(self, **kw: Any) -> Dict[str, Any]:
        """Handle LED control requests.
        
        Args:
            **kw: Request parameters (type, id)
            
        Returns:
            LED status or operation result
            
        Raises:
            cherrypy.HTTPError: On validation or operation errors
        """
        method: str = cherrypy.request.method
        led_type: Optional[str] = kw.get('type')
        drive_id: Optional[str] = kw.get('id')

        try:
            if method == 'PATCH':
                data: Dict[str, Any] = cherrypy.request.json
                state = data.get('state')
                result = self.led_handler.handle_patch_request(led_type, state, drive_id)
            else:
                result = self.led_handler.handle_get_request(led_type, drive_id)

        except ValueError as e:
            self.log.error(f"LED operation validation error: {e}")
            raise cherrypy.HTTPError(400, str(e))
        except HTTPError as e:
            self.log.error(f"LED operation HTTP error: {e}")
            raise cherrypy.HTTPError(e.code, e.reason)
        
        return result

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def get_led(self, **kw: Dict[str, Any]) -> Dict[str, Any]:
        return self.backend.get_led()

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['PATCH'])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.tools.auth_basic(on=True)
    def set_led(self, **kw: Dict[str, Any]) -> Dict[str, Any]:
        data = cherrypy.request.json
        rc = self.backend.set_led(data)

        if rc != 200:
            cherrypy.response.status = rc
            result = {'state': 'error: please, verify the data you sent.'}
        else:
            result = {'state': data['state'].lower()}
        return result

    def stop(self) -> None:
        self.unsubscribe()
        super().stop()


class NodeProxyApi(Thread):
    """Thread managing the Node Proxy REST API server."""

    def __init__(self, system: 'BaseSystem', reporter: 'Reporter', 
                 config: 'ConfigManager', username: str, password: str,
                 ssl_crt: str, ssl_key: str) -> None:
        """Initialize the API server thread.
        
        Args:
            system: System backend instance
            reporter: Reporter instance
            config: Configuration manager
            username: Authentication username
            password: Authentication password
            ssl_crt: SSL certificate content
            ssl_key: SSL key content
        """
        super().__init__()
        self.log = get_logger(__name__)
        self.cp_shutdown_event = Event()
        self.username = username
        self.password = password
        self.ssl_crt = ssl_crt
        self.ssl_key = ssl_key
        self.system = system
        self.reporter_agent = reporter
        self.config = config
        self.api = API(self.system, self.reporter_agent, self.config)
        
        # Setup server components
        self.ssl_manager = SslManager()
        self.server_config = ApiServerConfig(self.check_auth)
        self.lifecycle = ApiServerLifecycle(self.api, self.ssl_manager, 
                                           self.server_config)

    def check_auth(self, realm: str, username: str, password: str) -> bool:
        """Validate authentication credentials.
        
        Args:
            realm: Authentication realm
            username: Provided username
            password: Provided password
            
        Returns:
            True if credentials are valid
        """
        return self.username == username and self.password == password

    def shutdown(self) -> None:
        """Initiate graceful shutdown of the API server."""
        self.log.info('Stopping node-proxy API...')
        self.cp_shutdown_event.set()

    def run(self) -> None:
        """Run the API server (Thread main method)."""
        self.log.info('Starting node-proxy API server...')
        
        try:
            self.lifecycle.configure()
            self.lifecycle.mount_application()
            self.lifecycle.setup_ssl(self.ssl_crt, self.ssl_key)
            self.lifecycle.start()
            
            # Wait for shutdown signal
            self.cp_shutdown_event.wait()
            self.cp_shutdown_event.clear()
            
            self.lifecycle.stop()
            self.lifecycle.cleanup()
            
        except Exception as e:
            self.log.error(f'node-proxy API error: {e}')
            raise
