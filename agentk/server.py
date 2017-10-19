import hexdump
import logging
import os
import socket
import threading
import time
from select import select

logger = logging.getLogger(__name__)

# Common IO/select/etc sleep period, in seconds
io_sleep = 0.01


class Server(threading.Thread):
    def __init__(self, sock_fn='agentk.sock'):
        threading.Thread.__init__(self, target=self.run)

        # TODO: get this from config file or argument
        self._sock_file = os.environ['SSH_AUTH_SOCK'] if 'SSH_AUTH_SOCK' in os.environ else sock_fn
        self._sock = None
        self._conn = None
        self._addr = None
        self._exit = False

    @property
    def sock_fn(self):
        return self._sock_file

    def run(self):
        logger.debug('Running thread...')
        try:
            (self._conn, self._addr) = self.get_connection()
            self._communicate()
        except OSError as e:
            e.errno != 22 and logger.error(e)

    def _communicate(self):
        import fcntl
        oldflags = fcntl.fcntl(self._conn, fcntl.F_GETFL)
        fcntl.fcntl(self._conn, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)
        while not self._exit:
            events = select([self._conn], [], [], 0.5)
            for fd in events[0]:
                if self._conn == fd:
                    data = self._conn.recv(512)
                    if len(data) != 0:
                        # TODO: parse data
                        logger.debug('Data received (len: %d)', len(data))
                        logger.debug(hexdump.dump(data, size=8))

                    else:
                        self.close()
                        break
            time.sleep(io_sleep)

    def get_connection(self):
        """
        Return a pair of socket object and string address.

        May block!
        """

        self._sock = sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(self._sock_file)
            sock.listen(1)
            (conn, addr) = sock.accept()
            logger.debug('Connection accepted.')
            return conn, addr
        except:
            raise

    def close(self):
        logger.debug('Closing server thread...')
        self._exit = True
        try:
            if self._conn:
                self._conn.close()

            if self._sock:
                self._sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        if os.path.exists(self._sock_file):
            os.remove(self._sock_file)
