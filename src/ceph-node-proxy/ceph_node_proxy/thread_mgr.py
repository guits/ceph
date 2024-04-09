import signal
import threading
import traceback
import time
import logging
from typing import Any, List, Optional

logger = logging.getLogger('thread_mgr')
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class ThreadMgr:
    def __init__(self, thread_cls: List) -> None:
        self.stop = False
        self.threads: List[BaseThread] = []
        for c in thread_cls:
            self.threads.append(c())

    def add_thread(self, thread: 'BaseThread') -> None:
        self.threads.append(thread)

    def del_thread(self, thread: 'BaseThread') -> None:
        try:
            self.threads.remove(thread)
        except ValueError:
            pass

    def create_thread_from_cls(self, thread: 'BaseThread') -> None:
        thread_cls = thread.__class__
        self.del_thread(thread)
        t = thread_cls()
        self.add_thread(t)
        t.start()

    def start(self) -> None:
        self.loop()

    def shutdown(self) -> None:
        for t in self.threads:
            self.stop = True
            t.shutdown()

    def loop(self) -> None:
        while not self.stop:
            for t in self.threads:
                logger.debug(f'Checking thread {t.name}')
                try:
                    status = t.check_status()
                    label = 'Ok' if status else 'Critical'
                    logger.debug(f'Thread {t.name} status: {label}')
                except Exception as e:
                    exc = e.__class__.__name__
                    thread_class = t.name
                    logger.error(f'Thread {thread_class} not running: {exc}')
                    logger.debug(exc)
                    logger.info(f'Recreating thread {thread_class}')
                    self.create_thread_from_cls(t)
            time.sleep(3)


class BaseThread(threading.Thread):
    def __init__(self) -> None:
        super().__init__()
        self.exc: Optional[Exception] = None
        self.stop: bool = False
        self.name = self.__class__.__name__

    def run(self) -> None:
        logger.info(f'Starting {self.name}')
        try:
            self.loop()
        except Exception as e:
            self.exc = e
            return

    def shutdown(self) -> None:
        self.stop = True

    def check_status(self) -> bool:
        logger.debug(f'Checking status of {self.name}')
        if self.exc:
            traceback.print_tb(self.exc.__traceback__)
            logger.error(f'Caught exception: {self.exc.__class__.__name__}')
            logger.debug(self.exc)
            raise self.exc
        if not self.is_alive():
            logger.info(f'{self.name} not alive')
            self.start()
        return True

    def loop(self) -> None:
        raise NotImplementedError()


class Thread1(BaseThread):
    def __init__(self) -> None:
        super().__init__()

    def loop(self) -> None:
        while not self.stop:
            print(f'doing stuff from {self.name}')
            time.sleep(10)
            # raise RuntimeError("Thread1")


class Thread2(BaseThread):
    def __init__(self) -> None:
        super().__init__()

    def loop(self) -> None:
        while not self.stop:
            print(f'doing stuff from {self.name}')
            time.sleep(4)


def teardown(signum: Any, frame: Any, t_mgr: 'ThreadMgr') -> None:
    t_mgr.shutdown()
    print('SIGINT caught, shutting down threads...')
    exit(0)


def main() -> None:
    signal.signal(signal.SIGINT, lambda signum, frame: teardown(signum, frame, t_mgr))
    t_mgr = ThreadMgr([Thread1, Thread2])
    t_mgr.start()


if __name__ == '__main__':
    main()
