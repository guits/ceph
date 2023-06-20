try:
    import cherrypy
    from cherrypy._cpserver import Server
except ImportError:
    # to avoid sphinx build crash
    class Server:  # type: ignore
        pass

from typing import TYPE_CHECKING, Dict, Any, List
from cephadm.ssl_cert_utils import SSLCerts

if TYPE_CHECKING:
    from cephadm.module import CephadmOrchestrator


class NodeProxy:
    KV_STORE_NODE_PROXY_ROOT_CERT = 'node_proxy/root/cert'
    KV_STORE_NODE_PROXY_ROOT_KEY = 'node_proxy/root/key'

    def __init__(self, mgr: "CephadmOrchestrator", port: int = 8150) -> None:
        self.mgr = mgr
        self.server_port = port
        self.server_addr = self.mgr.get_mgr_ip()
        self.ssl_certs = SSLCerts()

    def configure_tls(self, server: Server) -> None:
        old_cert = self.mgr.get_store(self.KV_STORE_NODE_PROXY_ROOT_CERT)
        old_key = self.mgr.get_store(self.KV_STORE_NODE_PROXY_ROOT_KEY)
        if old_cert and old_key:
            self.ssl_certs.load_root_credentials(old_cert, old_key)
        else:
            self.ssl_certs.generate_root_cert(self.mgr.get_mgr_ip())
            self.mgr.set_store(self.KV_STORE_NODE_PROXY_ROOT_CERT, self.ssl_certs.get_root_cert())
            self.mgr.set_store(self.KV_STORE_NODE_PROXY_ROOT_KEY, self.ssl_certs.get_root_key())

        host = self.mgr.get_hostname()
        addr = self.mgr.get_mgr_ip()
        server.ssl_certificate, server.ssl_private_key = self.ssl_certs.generate_cert_files(host, addr)

    def configure_routes(self) -> None:
        d = cherrypy.dispatch.RoutesDispatcher()
        d.connect(name='root', route='/',
                  controller=self.root.POST,
                  conditions=dict(method=['POST']))
        c = {
            '/': {
                'request.dispatch': d,
            }
        }
        cherrypy.tree.mount(None, '/', config=c)

    def configure(self) -> None:
        self.root = Root(self.mgr, self.server_port, self.server_addr)
        self.configure_tls(self.root)
        self.configure_routes()
        # self.find_free_port()


class Root(Server):
    exposed = True

    def __init__(self,
                 mgr: "CephadmOrchestrator",
                 port: int,
                 host: str) -> None:
        self.mgr = mgr
        super().__init__()
        self.socket_port = port
        self.socket_host = host
        self.subscribe()
        self.data: Dict[str, Dict[str, Dict]] = {}

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def POST(self) -> Dict[str, Any]:

        self.data = cherrypy.request.json

        report = self.create_report()

        return report

    def create_report(self) -> Dict[str, List[Dict[str, Dict]]]:  # type: ignore
        mapping: Dict[str, str] = {
            'storage': 'NODE_PROXY_STORAGE',
            'memory': 'NODE_PROXY_MEMORY',
            'processors': 'NODE_PROXY_PROCESSORS',
            'network': 'NODE_PROXY_NETWORK',
        }
        report: Dict[str, Any] = dict()

        for component in self.data.keys():
            nok_members = self.get_nok_members(component)

            if nok_members:
                count = len(nok_members)
                self.mgr.set_health_warning(
                    mapping[component],
                    summary=f'{count} {component} member{"s" if count > 1 else ""} {"are" if count > 1 else "is"} not ok',
                    count=count,
                    detail=[f"{member['member']} is {member['status']}" for member in nok_members],
                )
                report[component] = dict()
                report[component] = nok_members

        return report

    def get_nok_members(self, component: str) -> List[Dict[str, str]]:
        nok_members: List[Dict[str, str]] = []

        for member in self.data[component].keys():
            _status = self.data[component][member]['status']['health'].lower()
            if _status.lower() != 'ok':
                _member = dict(
                    member=member,
                    status=_status,
                )
                nok_members.append(_member)

        return nok_members

    def stop(self) -> None:
        self.unsubscribe()
        super().stop()