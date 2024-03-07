import cherrypy  # type: ignore
import ip_addr
import socket
import ipaddress
import tempfile
import argparse
import os
import signal
import json
from cherrypy._cpserver import Server  # type: ignore
from threading import Thread, Event
from typing import Dict, List, Tuple, Any
from ceph_node_proxy.util import get_logger
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from dump_redfish_api import DEFAULT_DUMP_DIRECTORY  # type: ignore


class API(Server):
    auth_endpoint: str = '/redfish/v1/SessionService/Sessions'
    location: str = f'{auth_endpoint}/3'
    token: str = '1a4085674a970b18167f6327bb56b435'

    def __init__(self,
                 addr: str = '0.0.0.0',
                 port: int = 443,
                 dump_dir: str = DEFAULT_DUMP_DIRECTORY) -> None:
        super().__init__()
        self.log = get_logger(__name__)
        self.socket_port = port
        self.socket_host = addr
        self.subscribe()
        self.path: str = ''
        self.dump_dir: str = dump_dir

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def serve(self) -> Dict[str, str]:
        path: str = os.path.join(self.dump_dir, self.path)
        try:
            with open(path, 'r') as f:
                response_str = f.read()
        except OSError:
            raise cherrypy.HTTPError(404)
        return json.loads(response_str)

    def compare_vpath(self, vpath: List[str], path: str) -> bool:
        result: List[str] = path.split('/')
        return list(filter(None, result)) == vpath

    def empty_vpath(self, vpath: List[str]) -> None:
        while len(vpath) != 0:
            vpath.pop()

    def _cp_dispatch(self, vpath: List[str]) -> 'API':
        if self.compare_vpath(vpath, self.auth_endpoint):
            if cherrypy.request.method != 'POST':
                raise cherrypy.HTTPError(405)
            self.empty_vpath(vpath)
            vpath.append('fake_login')
            return self
        if self.compare_vpath(vpath, self.location):
            self.empty_vpath(vpath)
            if cherrypy.request.method == 'DELETE':
                vpath.append('fake_logout')
            if cherrypy.request.method == 'GET':
                vpath.append('fake_get_on_session')
            return self
        _path: List[str] = []
        while len(vpath) != 0:
            _path.append(vpath.pop(0))
        vpath.append('serve')
        self.path = '+'.join(_path)
        return self

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST'])
    @cherrypy.tools.json_out()
    def fake_login(self) -> str:
        # data: Dict[str, Any] = cherrypy.request.json
        # method: str = cherrypy.request.method
        cherrypy.response.headers['X-Auth-Token'] = API.token
        cherrypy.response.headers['Location'] = API.location
        cherrypy.response.status = 201
        return json.loads('{"@Message.ExtendedInfo":[{"Message":"The resource has been created successfully.","MessageArgs":[],"MessageArgs@odata.count":0,"MessageId":"Base.1.12.Created","RelatedProperties":[],"RelatedProperties@odata.count":0,"Resolution":"None.","Severity":"OK"},{"Message":"A new resource is successfully created.","MessageArgs":[],"MessageArgs@odata.count":0,"MessageId":"IDRAC.2.9.SYS414","RelatedProperties":[],"RelatedProperties@odata.count":0,"Resolution":"No response action is required.","Severity":"Informational"}],"@odata.context":"/redfish/v1/$metadata#Session.Session","@odata.id":"/redfish/v1/SessionService/Sessions/3","@odata.type":"#Session.v1_6_0.Session","ClientOriginIPAddress":"9.171.92.68","CreatedTime":"2024-03-14T17:06:19-05:00","Description":"User Session","Id":"3","Name":"User Session","Password":null,"SessionType":"Redfish","UserName":"root"}')  # noqa: E501

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['DELETE'])
    @cherrypy.tools.json_out()
    def fake_logout(self) -> str:
        return json.loads('{"@Message.ExtendedInfo":[{"Message":"The request completed successfully.","MessageArgs":[],"MessageArgs@odata.count":0,"MessageId":"Base.1.12.Success","RelatedProperties":[],"RelatedProperties@odata.count":0,"Resolution":"None","Severity":"OK"},{"Message":"The operation successfully completed.","MessageArgs":[],"MessageArgs@odata.count":0,"MessageId":"IDRAC.2.9.SYS413","RelatedProperties":[],"RelatedProperties@odata.count":0,"Resolution":"No response action is required.","Severity":"Informational"}]}')  # noqa: E501

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['GET'])
    @cherrypy.tools.json_out()
    def fake_get_on_session(self) -> str:
        return json.loads('{"@odata.context":"/redfish/v1/$metadata#Session.Session","@odata.id":"/redfish/v1/SessionService/Sessions/5","@odata.type":"#Session.v1_6_0.Session","ClientOriginIPAddress":"9.171.92.68","CreatedTime":"2024-03-15T13:33:11-05:00","Description":"User Session","Id":"3","Name":"User Session","Password":null,"SessionType":"Redfish","UserName":"root"}')  # noqa: E501

    @cherrypy.tools.json_out()
    def index(self) -> Dict[str, str]:
        # NoOp for now
        return {}


class FakeApi(Thread):
    def __init__(self, dump_dir: str = DEFAULT_DUMP_DIRECTORY) -> None:
        super().__init__()
        self.log = get_logger(__name__)
        self.cp_shutdown_event = Event()
        self.api = API(dump_dir=dump_dir)
        self.addr = ip_addr.get_first_addr()

    def shutdown(self) -> None:
        self.log.info('Stopping fake API...')
        self.cp_shutdown_event.set()

    def run(self) -> None:
        self.log.info('fake API configuration...')
        cherrypy.config.update({
            'environment': 'production',
            'engine.autoreload.on': False,
            'log.screen': True,
        })
        config = {'/': {
            'request.methods_with_bodies': ('POST', 'PUT', 'PATCH'),
            'tools.trailing_slash.on': False,
            'tools.auth_basic.realm': 'localhost',
        }}
        cherrypy.tree.mount(self.api, '/', config=config)
        self.generate_root_cert(self.addr)
        ssl_crt, ssl_key = self.generate_cert_files()
        self.api.ssl_certificate = ssl_crt
        self.api.ssl_private_key = ssl_key

        cherrypy.server.unsubscribe()
        try:
            cherrypy.engine.start()
            self.log.info('fake API started.')
            self.cp_shutdown_event.wait()
            self.cp_shutdown_event.clear()
            cherrypy.engine.exit()
            cherrypy.server.httpserver = None
            self.log.info('fake API shutdown.')
        except Exception as e:
            self.log.error(f'fake API error: {e}')

    def generate_root_cert(self, addr: str) -> Tuple[str, str]:
        self.root_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend())
        root_public_key = self.root_key.public_key()
        root_builder = x509.CertificateBuilder()
        root_builder = root_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'fakeredfishapi-root'),
        ]))
        root_builder = root_builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'fakeredfishapi-root'),
        ]))
        root_builder = root_builder.not_valid_before(datetime.now())
        root_builder = root_builder.not_valid_after(datetime.now() + timedelta(days=(365 * 10 + 3)))
        root_builder = root_builder.serial_number(x509.random_serial_number())
        root_builder = root_builder.public_key(root_public_key)
        root_builder = root_builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(addr))]
            ),
            critical=False
        )
        root_builder = root_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        root_cert = root_builder.sign(
            private_key=self.root_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        cert_str = root_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        key_str = self.root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        return (cert_str, key_str)

    def generate_cert_files(self) -> Tuple[str, str]:
        cert, key = self.generate_certificates()
        self.cert_file = tempfile.NamedTemporaryFile()
        self.cert_file.write(cert.encode('utf-8'))
        self.cert_file.flush()  # cert_tmp must not be gc'ed

        self.key_file = tempfile.NamedTemporaryFile()
        self.key_file.write(key.encode('utf-8'))
        self.key_file.flush()  # pkey_tmp must not be gc'ed

        return self.cert_file.name, self.key_file.name

    def generate_certificates(self) -> Tuple[str, str]:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend())
        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.addr), ]))
        builder = builder.issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'fake-redfish-api'), ]))
        builder = builder.not_valid_before(datetime.now())
        builder = builder.not_valid_after(datetime.now() + timedelta(days=(365 * 10 + 3)))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        af_inet_addrs = ip_addr.get_ip_addrs(socket.AF_INET)
        for iface in af_inet_addrs.keys():
            for addr in af_inet_addrs[iface]:
                ip = x509.IPAddress(ipaddress.ip_address(addr))
                try:
                    builder = builder.add_extension(x509.SubjectAlternativeName([ip]), critical=False)
                except ValueError:
                    pass
        builder = builder.add_extension(x509.BasicConstraints(
            ca=False, path_length=None), critical=True,)

        cert = builder.sign(private_key=self.root_key,
                            algorithm=hashes.SHA256(), backend=default_backend())
        cert_str = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        key_str = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption()
                                            ).decode('utf-8')

        return (cert_str, key_str)


def signal_handler(signum: Any, frame: Any, fakeapi: FakeApi) -> None:
    print('Shutting down fake API...')
    fakeapi.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(prog='fake redfish api.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--dump-dir',
                        dest='dump_dir',
                        help='the path to dumps.',
                        required=False,
                        default=DEFAULT_DUMP_DIRECTORY)
    args = parser.parse_args()
    fakeapi = FakeApi(args.dump_dir)
    signal.signal(signal.SIGINT, lambda signum, frame: signal_handler(signum, frame, fakeapi))
    fakeapi.run()
    fakeapi.shutdown()


if __name__ == '__main__':
    main()
