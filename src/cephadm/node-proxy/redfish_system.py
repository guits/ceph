from system import System
from redfish_client import RedFishClient
from threading import Thread, Lock
from time import sleep
from util import Logger
from typing import Dict, Any

log = Logger(__name__)


class RedfishSystem(System):
    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.host: str = kw['host']
        self.username: str = kw['username']
        self.password: str = kw['password']
        self.system_endpoint = kw.get('system_endpoint', '/Systems/1')
        log.logger.info(f"redfish system initialization, host: {self.host}, user: {self.username}")
        self.client = RedFishClient(self.host, self.username, self.password)

        self._system: Dict[str, Dict[str, Any]] = {}
        self.run: bool = False
        self.thread: Thread
        self.start_client()
        self.data_ready: bool = False
        self.previous_data: Dict = {}
        self.lock: Lock = Lock()

    def start_client(self) -> None:
        log.logger.info(f"redfish system initialization, host: {self.host}, user: {self.username}")
        self.client = RedFishClient(self.host, self.username, self.password)
        self.client.login()

    def get_system(self) -> Dict[str, Dict[str, Dict]]:
        result = {
            'storage': self.get_storage(),
            'processors': self.get_processors(),
            'network': self.get_network(),
        }
        return result

    def get_status(self) -> Dict[str, Dict[str, Dict]]:
        return self._system['status']

    def get_metadata(self) -> Dict[str, Dict[str, Dict]]:
        return self._system['metadata']

    def get_memory(self) -> Dict[str, Dict[str, Dict]]:
        return self._system['memory']

    def get_power(self) -> Dict[str, Dict[str, Dict]]:
        return self._system['power']

    def get_processors(self) -> Dict[str, Dict[str, Dict]]:
        return self._system['processors']

    def get_network(self) -> Dict[str, Dict[str, Dict]]:
        return self._system['network']

    def get_storage(self) -> Dict[str, Dict[str, Dict]]:
        return self._system['storage']

    def _update_system(self) -> None:
        redfish_system = self.client.get_path(self.system_endpoint)
        self._system = {**redfish_system, **self._system}

    def _update_metadata(self) -> None:
        raise NotImplementedError()

    def _update_memory(self) -> None:
        raise NotImplementedError()

    def _update_power(self) -> None:
        raise NotImplementedError()

    def _update_network(self) -> None:
        raise NotImplementedError()

    def _update_processors(self) -> None:
        raise NotImplementedError()

    def _update_storage(self) -> None:
        raise NotImplementedError()

    def start_update_loop(self) -> None:
        self.run = True
        self.thread = Thread(target=self.update)
        self.thread.start()

    def stop_update_loop(self) -> None:
        self.run = False
        self.thread.join()

    def update(self) -> None:
        #  this loop can have:
        #  - caching logic
        try:
            while self.run:
                log.logger.debug("waiting for a lock.")
                self.lock.acquire()
                log.logger.debug("lock acquired.")
                try:
                    self._update_system()
                    # following calls in theory can be done in parallel
                    self._update_metadata()
                    self._update_memory()
                    self._update_power()
                    self._update_network()
                    self._update_processors()
                    self._update_storage()
                    self.data_ready = True
                    sleep(5)
                finally:
                    self.lock.release()
                    log.logger.debug("lock released.")
        # Catching 'Exception' is probably not a good idea (devel only)
        except Exception as e:
            log.logger.error(f"Error detected, logging out from redfish api.\n{e}")
            self.client.logout()
            raise
