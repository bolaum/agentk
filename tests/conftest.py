import base64
import hexdump
import logging
import os
import struct
from pytest import fixture
from time import sleep

from agentk.server import Server
from agentk import log
from agentk.kkmip_interface import KkmipInterface, KkmipKey

log.setup('debug')

logger = logging.getLogger(__name__)

SOCK_FILE = 'agentk.sock'
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def rsa_pem_to_exp_mod(keydata):
    parts = []
    while keydata:
        # read the length of the data
        dlen = struct.unpack('>I', keydata[:4])[0]

        # read in <length> bytes
        data, keydata = keydata[4:dlen + 4], keydata[4 + dlen:]

        parts.append(data)

    # logger.debug('Exponent:')
    # for l in hexdump.hexdump(parts[1], result='generator'):
    #     logger.debug(l)
    #
    # logger.debug('Modulus:')
    # for l in hexdump.hexdump(parts[2], result='generator'):
    #     logger.debug(l)

    return parts[1], parts[2]


@fixture(scope='session')
def key():
    with open(os.path.join(DATA_DIR, 'testkey.pub'), 'r') as f:
        data = f.read().split(None)[1]

    pubkey = base64.b64decode(data)

    # with open(os.path.join(DATA_DIR, 'testkey'), 'r') as f:
    #     privkey = f.read()

    return rsa_pem_to_exp_mod(pubkey), None


@fixture(scope='session')
def kkmip_stub(key):
    pubkey, privkey = key

    class KkmipInterfaceStub(KkmipInterface):
        def __init__(self):
            self._keys = [KkmipKey(pubkey, 'testkey')]

    return KkmipInterfaceStub()


@fixture(scope='session')
def server(kkmip_stub):
    os.environ["SSH_AUTH_SOCK"] = os.path.abspath('agentk.sock')

    if os.path.exists(SOCK_FILE):
        os.remove(SOCK_FILE)

    server = Server(kkmip_stub, sock_fn=SOCK_FILE)
    server.start()
    sleep(1)

    yield server

    server.close()
