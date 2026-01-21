from ceph_node_proxy.redfishdellsystem import RedfishDellSystem
from ceph_node_proxy.api import NodeProxyApi
from ceph_node_proxy.reporter import Reporter
from ceph_node_proxy.config import ConfigManager, AppConfig
from ceph_node_proxy.util import get_logger, http_req, write_tmp_file
from urllib.error import HTTPError
from typing import Dict, Any, Optional

import argparse
import os
import ssl
import json
import time
import signal


class NodeProxyManager:
    """Main manager orchestrating the node proxy components.
    
    This class manages the lifecycle of the system backend, reporter,
    and API server components with proper dependency injection.
    """

    def __init__(self, mgr_host: str, cephx_name: str, cephx_secret: str,
                 ca_path: str, api_ssl_crt: str, api_ssl_key: str,
                 mgr_agent_port: str, config_file: Optional[str] = None,
                 reporter_scheme: str = 'https',
                 reporter_endpoint: str = '/node-proxy/data') -> None:
        """Initialize the Node Proxy Manager.
        
        Args:
            mgr_host: Manager host address
            cephx_name: Ceph authentication name
            cephx_secret: Ceph authentication secret
            ca_path: Path to CA certificate
            api_ssl_crt: SSL certificate for API
            api_ssl_key: SSL key for API
            mgr_agent_port: Manager agent port
            config_file: Optional path to configuration file
            reporter_scheme: Reporter URL scheme (default: https)
            reporter_endpoint: Reporter endpoint path
        """
        self.exc: Optional[Exception] = None
        self.log = get_logger(__name__)
        self.mgr_host: str = mgr_host
        self.cephx_name: str = cephx_name
        self.cephx_secret: str = cephx_secret
        self.ca_path: str = ca_path
        self.api_ssl_crt: str = api_ssl_crt
        self.api_ssl_key: str = api_ssl_key
        self.mgr_agent_port: str = str(mgr_agent_port)
        self.stop: bool = False
        self.reporter_scheme: str = reporter_scheme
        self.reporter_endpoint: str = reporter_endpoint
        
        # Setup SSL context
        self.ssl_ctx = self._create_ssl_context()
        
        # Setup authentication
        self.cephx = {'cephx': {'name': self.cephx_name,
                                'secret': self.cephx_secret}}
        
        # Load configuration
        self.config = ConfigManager(config_file or '/etc/ceph/node-proxy.yml')
        
        # OOB credentials (populated during init)
        self.username: str = ''
        self.password: str = ''

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create and configure SSL context.
        
        Returns:
            Configured SSL context
        """
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = True
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        ssl_ctx.load_verify_locations(self.ca_path)
        return ssl_ctx

    def run(self) -> None:
        """Run the node proxy manager (main entry point)."""
        self.init()
        self.loop()

    def init(self) -> None:
        """Initialize all components."""
        self.init_system()
        self.init_reporter()
        self.init_api()

    def fetch_oob_details(self) -> Dict[str, str]:
        """Fetch out-of-band management details from the manager.
        
        Returns:
            Dictionary containing host, username, password, and port
            
        Raises:
            HTTPError: If the request to the manager fails
        """
        try:
            headers, result, status = http_req(hostname=self.mgr_host,
                                               port=self.mgr_agent_port,
                                               data=json.dumps(self.cephx),
                                               endpoint='/node-proxy/oob',
                                               ssl_ctx=self.ssl_ctx)
        except HTTPError as e:
            msg = f'No out of band tool details could be loaded: {e.code}, {e.reason}'
            self.log.debug(msg)
            raise

        result_json = json.loads(result)
        oob_details: Dict[str, str] = {
            'host': result_json['result']['addr'],
            'username': result_json['result']['username'],
            'password': result_json['result']['password'],
            'port': result_json['result'].get('port', '443')
        }
        return oob_details

    def init_system(self) -> None:
        """Initialize the system backend (Redfish).
        
        Fetches OOB credentials and creates the system backend instance.
        
        Raises:
            SystemExit: If OOB details cannot be loaded
            RuntimeError: If system initialization fails
        """
        try:
            oob_details = self.fetch_oob_details()
            self.username = oob_details['username']
            self.password = oob_details['password']
        except HTTPError:
            self.log.warning('No oob details could be loaded, exiting...')
            raise SystemExit(1)
        try:
            self.system = RedfishDellSystem(
                host=oob_details['host'],
                port=oob_details['port'],
                username=oob_details['username'],
                password=oob_details['password'],
                config=self.config
            )
            self.system.start()
        except RuntimeError:
            self.log.error("Can't initialize the redfish system.")
            raise

    def init_reporter(self) -> None:
        """Initialize and start the reporter component.
        
        Raises:
            RuntimeError: If reporter initialization fails
        """
        try:
            self.reporter_agent = Reporter(
                system=self.system,
                cephx=self.cephx,
                reporter_scheme=self.reporter_scheme,
                reporter_hostname=self.mgr_host,
                reporter_port=self.mgr_agent_port,
                reporter_endpoint=self.reporter_endpoint
            )
            self.reporter_agent.start()
        except RuntimeError:
            self.log.error("Can't initialize the reporter.")
            raise

    def init_api(self) -> None:
        """Initialize and start the API server.
        
        Raises:
            Exception: If API initialization fails
        """
        try:
            self.log.info('Starting node-proxy API...')
            self.api = NodeProxyApi(
                system=self.system,
                reporter=self.reporter_agent,
                config=self.config,
                username=self.username,
                password=self.password,
                ssl_crt=self.api_ssl_crt,
                ssl_key=self.api_ssl_key
            )
            self.api.start()
        except Exception as e:
            self.log.error(f"Can't start node-proxy API: {e}")
            raise

    def loop(self) -> None:
        """Main monitoring loop checking thread health.
        
        Monitors the system and reporter threads, restarting them if necessary.
        Runs until self.stop is set to True.
        """
        while not self.stop:
            for thread in [self.system, self.reporter_agent]:
                try:
                    status = thread.check_status()
                    label = 'Ok' if status else 'Critical'
                    self.log.debug(f'{thread} status: {label}')
                except Exception as e:
                    self.log.error(f'{thread} not running: {e.__class__.__name__}: {e}')
                    thread.shutdown()
                    self.init_system()
                    self.init_reporter()
            self.log.debug('All threads are alive, next check in 20sec.')
            time.sleep(20)

    def shutdown(self) -> None:
        """Gracefully shutdown all components."""
        self.stop = True
        # if `self.system.shutdown()` is called before self.start(), it will fail.
        if hasattr(self, 'api'):
            self.api.shutdown()
        if hasattr(self, 'reporter_agent'):
            self.reporter_agent.shutdown()
        if hasattr(self, 'system'):
            self.system.shutdown()

    def request_system_shutdown(self) -> None:
        """Request graceful shutdown of the system backend."""
        if hasattr(self, 'system'):
            self.system.request_shutdown()

    def logout_system(self) -> None:
        """Logout from the system backend (e.g., Redfish)."""
        if hasattr(self, 'system'):
            self.system.logout()


def handler(signum: Any, frame: Any, t_mgr: 'NodeProxyManager') -> None:
    """Handle SIGTERM signal for graceful shutdown.
    
    Args:
        signum: Signal number
        frame: Current stack frame
        t_mgr: Node proxy manager instance
    """
    t_mgr.log.info('SIGTERM caught, shutting down threads...')
    t_mgr.request_system_shutdown()
    t_mgr.shutdown()
    t_mgr.log.info('Logging out from RedFish API')
    t_mgr.logout_system()
    raise SystemExit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Ceph Node-Proxy for HW Monitoring',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '--config',
        help='path of config file in json format',
        required=True
    )
    parser.add_argument(
        '--debug',
        help='increase logging verbosity (debug level)',
        action='store_true',
    )

    args = parser.parse_args()
    if args.debug:
        CONFIG['logging']['level'] = 10

    if not os.path.exists(args.config):
        raise Exception(f'No config file found at provided config path: {args.config}')

    with open(args.config, 'r') as f:
        try:
            config_json = f.read()
            config = json.loads(config_json)
        except Exception as e:
            raise Exception(f'Failed to load json config: {str(e)}')

    target_ip = config['target_ip']
    target_port = config['target_port']
    keyring = config['keyring']
    root_cert = config['root_cert.pem']
    listener_cert = config['listener.crt']
    listener_key = config['listener.key']
    name = config['name']

    ca_file = write_tmp_file(root_cert,
                             prefix_name='cephadm-endpoint-root-cert')

    node_proxy_mgr = NodeProxyManager(
        mgr_host=target_ip,
        cephx_name=name,
        cephx_secret=keyring,
        mgr_agent_port=target_port,
        ca_path=ca_file.name,
        api_ssl_crt=listener_cert,
        api_ssl_key=listener_key,
        config_file='/etc/ceph/node-proxy.yml'
    )
    signal.signal(signal.SIGTERM,
                  lambda signum, frame: handler(signum, frame, node_proxy_mgr))
    node_proxy_mgr.run()


if __name__ == '__main__':
    main()
