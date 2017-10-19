import hexdump
import logging
import os
import socket
import struct
import threading
import time
from paramiko.message import Message
from paramiko.py3compat import byte_chr
from paramiko.ssh_exception import SSHException
from select import select

logger = logging.getLogger(__name__)

# Common IO/select/etc sleep period, in seconds
io_sleep = 0.01

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14

MSG_TYPES = {
    SSH_AGENTC_REQUEST_IDENTITIES: 'SSH_AGENTC_REQUEST_IDENTITIES',
    SSH_AGENT_IDENTITIES_ANSWER: 'SSH_AGENT_IDENTITIES_ANSWER',
    SSH_AGENTC_SIGN_REQUEST: 'SSH_AGENTC_SIGN_REQUEST',
    SSH_AGENT_SIGN_RESPONSE: 'SSH_AGENT_SIGN_RESPONSE',
}


class Server(threading.Thread):
    def __init__(self, kkmip_interace, sock_fn=None):
        threading.Thread.__init__(self, target=self.run)

        self._kkmip = kkmip_interace

        # TODO: get this from config file or argument
        self._sock_file = 'agentk.sock'

        if sock_fn:
            self._sock_file = sock_fn
        elif 'SSH_AUTH_SOCK' in os.environ :
            self._sock_file = os.environ['SSH_AUTH_SOCK']

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
            (self._conn, self._addr) = self._get_connection()
            self._communicate()
        except OSError as e:
            if e.errno != 22:
                logger.error(e)

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

    def _communicate(self):
        import fcntl
        oldflags = fcntl.fcntl(self._conn, fcntl.F_GETFL)
        fcntl.fcntl(self._conn, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)
        while not self._exit:
            events = select([self._conn], [], [], 0.5)
            for fd in events[0]:
                try:
                    msg_type, msg = self._get_message()
                    logger.debug('Message received: %s', MSG_TYPES[msg_type])
                    for l in hexdump.hexdump(msg.asbytes(), result='generator'):
                        logger.debug(l)

                    if msg_type == SSH_AGENTC_REQUEST_IDENTITIES:
                        self._send_identities()
                    elif msg_type == SSH_AGENTC_SIGN_REQUEST:
                        raise NotImplemented

                except SSHException:
                    self.close()
                    break
            time.sleep(io_sleep)

    def _get_connection(self):
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

    def _get_message(self):
        msg_size = self._read_all(4)
        msg = Message(self._read_all(struct.unpack('>I', msg_size)[0]))
        # get message type
        return ord(msg.get_byte()), msg

    def _read_all(self, wanted):
        result = self._conn.recv(wanted)
        while len(result) < wanted:
            if len(result) == 0:
                raise SSHException('lost client')
            extra = self._conn.recv(wanted - len(result))
            if len(extra) == 0:
                raise SSHException('lost client')
            result += extra
        return result

    def _send_reply(self, msg):
        msg_bytes = msg.asbytes()
        data = struct.pack('>I', len(msg_bytes)) + msg_bytes

        logger.debug('Sending reply...')
        for l in hexdump.hexdump(data, result='generator'):
            logger.debug(l)

        self._conn.send(data)

    def _send_identities(self):
        msg = Message()

        kkmip_keys = self._kkmip.get_keys()

        # add response byte
        msg.add_byte(byte_chr(SSH_AGENT_IDENTITIES_ANSWER))
        # add number of keys
        msg.add_int(len(kkmip_keys))

        for key in self._kkmip.get_keys():
            # add key in PEM format
            msg.add_string(key.get_pem_bytes())
            # add comment
            msg.add_string(key.get_comment())

        self._send_reply(msg)
