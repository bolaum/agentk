import hexdump
import logging
import os
import socket
import struct
import textwrap
import threading
import time
from binascii import hexlify
from hashlib import md5
from paramiko.message import Message
from paramiko.py3compat import byte_chr
from paramiko.ssh_exception import SSHException
from select import select

logger = logging.getLogger(__name__)

# Common IO/select/etc sleep period, in seconds
io_sleep = 0.01

SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_ADD_IDENTITY = 17
SSH_AGENTC_REMOVE_IDENTITY = 18
SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19

MSG_TYPES = {
    SSH_AGENTC_REQUEST_IDENTITIES: 'SSH_AGENTC_REQUEST_IDENTITIES',
    SSH_AGENTC_SIGN_REQUEST: 'SSH_AGENTC_SIGN_REQUEST',
    SSH_AGENTC_ADD_IDENTITY: 'SSH_AGENTC_ADD_IDENTITY',
    SSH_AGENTC_REMOVE_IDENTITY: 'SSH_AGENTC_REMOVE_IDENTITY',
    SSH_AGENTC_REMOVE_ALL_IDENTITIES: 'SSH_AGENTC_REMOVE_ALL_IDENTITIES'
}


class Server(threading.Thread):
    def __init__(self, kkmip_interace, sock_fn=None):
        threading.Thread.__init__(self, target=self.run)

        self._kkmip = kkmip_interace
        self._sock_file = sock_fn
        self._sock = None
        self._conn = None
        self._addr = None
        self._exit = False

    @property
    def sock_fn(self):
        return self._sock_file

    def run(self):
        logger.debug('Running thread...')
        self._bind_to_sock()
        while True:
            try:
                (self._conn, self._addr) = self._get_connection()
                self._communicate()
            except OSError as e:
                if e.errno != 22:
                    logger.exception(e)
                self.close()
                break
            except SSHException as e:
                logger.debug(e)
            except Exception as e:
                logger.exception(e)
                self.close()
                break

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


                    if not msg_type in MSG_TYPES:
                        logger.warning('Unknown message received: %s', msg_type)
                        self._send_failure()
                        continue

                    logger.debug('Message received: %s', MSG_TYPES[msg_type])

                    for l in hexdump.hexdump(msg.asbytes(), result='generator'):
                        logger.debug(l)

                    if msg_type == SSH_AGENTC_REQUEST_IDENTITIES:
                        self._send_identities()
                    elif msg_type == SSH_AGENTC_SIGN_REQUEST:
                        self._send_sign_data(msg)
                    elif msg_type == SSH_AGENTC_ADD_IDENTITY:
                        self._add_key(msg)
                    elif msg_type == SSH_AGENTC_REMOVE_IDENTITY:
                        self._remove_key(msg)
                    elif msg_type == SSH_AGENTC_REMOVE_ALL_IDENTITIES:
                        self._remove_all_keys()
                except SSHException:
                    raise
            time.sleep(io_sleep)

    def _bind_to_sock(self):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self._sock_file)
        logger.debug("socket file created: %s", self._sock_file)

    def _get_connection(self):
        """
        Return a pair of socket object and string address.

        May block!
        """

        try:
            self._sock.listen(1)
            (conn, addr) = self._sock.accept()
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
        while True:
            try:
                result = self._conn.recv(wanted)
                break
            except BlockingIOError:
                continue

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

    def _send_failure(self):
        msg = Message()
        msg.add_byte(byte_chr(SSH_AGENT_FAILURE))
        self._send_reply(msg)

    def _send_success(self):
        msg = Message()
        msg.add_byte(byte_chr(SSH_AGENT_SUCCESS))
        self._send_reply(msg)

    def _send_identities(self):
        msg = Message()

        kkmip_keys = self._kkmip.get_keys()

        # add response byte
        msg.add_byte(byte_chr(SSH_AGENT_IDENTITIES_ANSWER))
        # add number of keys
        msg.add_int(len(kkmip_keys))

        for key in self._kkmip.get_keys():
            for l in textwrap.wrap(key.get_openssh_pubkey_format(), width=58):
                logger.debug(l)
            # add key in PEM format
            msg.add_string(key.get_pem_bytes())
            # add comment
            msg.add_string(key.get_comment())

        self._send_reply(msg)

    def _send_sign_data(self, msg):
        logger.debug('Sending signed data...')
        blob = msg.get_string()
        data = msg.get_string()
        flags = msg.get_int()

        logger.debug('Key blob:')
        for l in hexdump.hexdump(blob, result='generator'):
            logger.debug(l)

        # logger.debug('Data to be signed:')
        # for l in hexdump.hexdump(data, result='generator'):
        #     logger.debug(l)
        #

        # logger.debug('Flags: %X', flags)

        signed_data = self._sign_data(blob, data)

        if not signed_data:
            self._send_failure()
            return

        sign_blob = Message()
        sign_blob.add_string('ssh-rsa')
        sign_blob.add_string(signed_data)

        msg = Message()
        # add response byte
        msg.add_byte(byte_chr(SSH_AGENT_SIGN_RESPONSE))
        # add signed blob
        msg.add_string(sign_blob.asbytes())

        self._send_reply(msg)

    def _sign_data(self, blob, data):
        fingerprint = md5(blob).digest()

        key = self._kkmip.get_cached_key_by_fingerprint(fingerprint)
        if not key:
            return None

        logger.debug('Key found: %s', hexlify(key.get_fingerprint()).decode('ascii'))

        return key.sign(data)

    def _add_key(self, msg):
        key_type = msg.get_string().decode('ascii')

        if key_type != str('ssh-rsa'):
            logger.error('Key type %s is not supported', key_type)
            self._send_failure()
            return

        n = msg.get_mpint()
        e = msg.get_mpint()
        d = msg.get_mpint()
        iqmp = msg.get_mpint()
        p = msg.get_mpint()
        q = msg.get_mpint()
        comment = msg.get_string().decode('ascii')

        try:
            self._kkmip.import_key(n, e, d, p, q, comment)
            self._send_success()
        except:
            self._send_failure()

    def _remove_key(self, msg):
        blob = msg.get_string()
        fingerprint = md5(blob).digest()

        logger.debug('Removing key %s...', hexlify(fingerprint).decode('ascii'))
        for k in self._kkmip.get_keys():
            logger.debug(hexlify(k.get_fingerprint()).decode('ascii'))
        key = self._kkmip.get_cached_key_by_fingerprint(fingerprint)

        if not key:
            logger.error('Key not found.')
            self._send_failure()
            return

        self._kkmip.destroy_key(key)
        self._send_success()

    def _remove_all_keys(self):
        logger.debug('Removing all keys...')
        self._kkmip.destroy_keys()
        self._send_success()
