from threading import Thread
import requests
import time
from util import logger

log = logger(__name__, level=10)

class Reporter:
    def __init__(self, system, observer_url):
        self.system = system
        self.observer_url = observer_url
        self.finish = False

    def stop(self):
        self.finish = True
        self.thread.join()

    def run(self):
        self.thread = Thread(target=self.loop)
        self.thread.start()

    def loop(self):
        while not self.finish:
            # Any logic to avoid sending the all the system
            # information every loop can go here. In a real
            # scenario probably we should just send the sub-parts
            # that have changed to minimize the traffic in
            # dense clusters
            if self.system.data_ready:
                log.debug("waiting for a lock.")
                try:
                    self.system.lock.acquire()
                    log.debug("lock acquired.")
                    if not self.system.get_system() == self.system.previous_data:
                        self.system.previous_data = self.system.get_system()
                        log.info('data has changed since last iteration.')
                        d = self.system.get_system()
                        requests.post(f"{self.observer_url}/fake_endpoint", json=d)
                    else:
                        log.info('no diff, not sending data to the mgr.')
                finally:
                    self.system.lock.release()
                    log.debug("lock released.")
            time.sleep(20)
