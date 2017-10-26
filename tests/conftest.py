import base64
import codecs
import hexdump
import logging
import os
import struct
from pytest import fixture
from time import sleep

from agentk.server import Server
from agentk import log
from agentk.kkmip_interface import KkmipInterface, KkmipKey
from agentk.utils import bigint_to_bytes
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1_modules.rfc2437 import RSAPrivateKey, RSAPublicKey
from pyasn1_modules.rfc2459 import SubjectPublicKeyInfo

log.setup('debug')

logger = logging.getLogger(__name__)

SOCK_FILE = 'agentk.sock'
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


@fixture(scope='session')
def privkey_fn():
    return os.path.join(DATA_DIR, 'testkey')


@fixture(scope='session')
def kkmip_stub(privkey_fn):
    class KkmipKeyStub(KkmipKey):
        def __init__(self, pubkey_der):
            self._name = 'testkey'
            self._pubkey_der = pubkey_der
            self._pub_key_bytes = None
            self._gen_pem()

        def _fetch_material(self):
            subject_public_key, rest_of_input = der_decoder(self._pubkey_der, asn1Spec=SubjectPublicKeyInfo())
            bin = subject_public_key['subjectPublicKey'].asOctets()
            public_key, rest_of_input = der_decoder(bin, asn1Spec=RSAPublicKey())

            return int(public_key['publicExponent']), int(public_key['modulus'])

    class KkmipInterfaceStub(KkmipInterface):
        def __init__(self):
            pubkey_der, _ = self._get_keys_der(privkey_fn)
            self._keys = [KkmipKeyStub(pubkey_der)]

        def get_keys(self):
            return self._keys

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


@fixture(scope='session')
def kkmip():
    kk = KkmipInterface('kryptus.dyndns.biz', 49252,
                        cert=('/home/bolaum/projs/desafiok/vhsm_12/user1.crt',
                              '/home/bolaum/projs/desafiok/vhsm_12/user1.key'))


    return kk

