from threading import Thread
import requests
import time
from .util import Logger
from typing import Dict, Any


class Reporter:
    def __init__(self, system: Any, data: Dict[str, Any], observer_url: str) -> None:
        self.system = system
        self.observer_url = observer_url
        self.finish = False
        self.data = data
        self.log = Logger(__name__)
        self.log.logger.info(f'Observer url set to {self.observer_url}')

    def stop(self) -> None:
        self.finish = True
        self.thread.join()

    def run(self) -> None:
        self.thread = Thread(target=self.loop)
        self.thread.start()

    def loop(self) -> None:
        while not self.finish:
            # Any logic to avoid sending the all the system
            # information every loop can go here. In a real
            # scenario probably we should just send the sub-parts
            # that have changed to minimize the traffic in
            # dense clusters
            self.log.logger.debug("waiting for a lock.")
            self.system.lock.acquire()
            self.log.logger.debug("lock acquired.")
            if self.system.data_ready:
                self.log.logger.info('data ready to be sent to the mgr.')
                if not self.system.get_system() == self.system.previous_data:
                    self.log.logger.info('data has changed since last iteration.')
                    self.data['data'] = self.system.get_system()
                    try:
                        # TODO: add a timeout parameter to the reporter in the config file
                        self.log.logger.info(f"sending data to {self.observer_url}")
                        r = requests.post(f"{self.observer_url}", json=self.data, timeout=5, verify=False)
                    except (requests.exceptions.RequestException,
                            requests.exceptions.ConnectionError) as e:
                        self.log.logger.error(f"The reporter couldn't send data to the mgr: {e}")
                        # Need to add a new parameter 'max_retries' to the reporter if it can't
                        # send the data for more than x times, maybe the daemon should stop altogether
                    else:
                        self.system.previous_data = self.system.get_system()
                else:
                    self.log.logger.info('no diff, not sending data to the mgr.')
            self.system.lock.release()
            self.log.logger.debug("lock released.")
            time.sleep(5)
