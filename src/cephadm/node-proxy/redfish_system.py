from system import System
from redfish_client import RedFishClient
from threading import Thread
from time import sleep
from flask import request
from util import logger

log = logger(__name__)


class RedfishSystem(System):
    def __init__(self, host, username, password):
        log.info(f"redfish system initialization, host: {host}, user: {username}")
        self.client = RedFishClient(host, username, password)
        self.client.login()
        self._system = {}
        self.run = False
        self.thread = None

    def get_system(self):
        return self._system

    def get_status(self):
        return self._system['Status']

    def get_metadata(self):
        return self._system['metadata']

    def get_memory(self):
        return self._system['memory']

    def get_power(self):
        return self._system['power']

    def get_processor(self):
        return self._system['processor']

    def get_network(self):
        return self._system['network']

    def get_storage(self):
        return self._system['storage']

    def _process_redfish_system(self, redfish_system):
        return redfish_system

    def _update_system(self):
        redfish_system = self.client.get_path('/Systems/1')
        self._system = self._process_redfish_system(redfish_system)

    def _update_metadata(self):
        log.info("Updating metadata")
        pass

    def _update_memory(self):
        log.info("Updating memory")
        pass

    def _update_power(self):
        log.info("Updating power")
        pass

    def _update_network(self):
        net_path = self._system['EthernetInterfaces']['@odata.id']
        log.info("Updating network")
        network_info = self.client.get_path(net_path)
        self._system['network'] = {}
        for interface in network_info['Members']:
            interface_path = interface['@odata.id']
            interface_info = self.client.get_path(interface_path)
            self._system['network'][interface_info['Id']] = interface_info

    def _update_storage(self):
        log.info("Updating storage")
        pass

    def start_update_loop(self):
        self.run = True
        self.thread = Thread(target=self.update)
        self.thread.start()

    def stop_update_loop(self):
        self.run = False
        self.thread.join()

    def update(self):
        #  this loop can have:
        #  - caching logic
        while self.run:
            self._update_system()
            # following calls in theory can be done in parallel
            self._update_metadata()
            self._update_memory()
            self._update_power()
            self._update_network()
            self._update_storage()
            sleep(3)
