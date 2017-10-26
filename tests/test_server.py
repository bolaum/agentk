import logging
import paramiko
from binascii import hexlify

logger = logging.getLogger(__name__)


def test_server_connection(server):
    agent = paramiko.Agent()
    keys = agent.get_keys()

    assert len(keys) == 1
    assert keys[0].get_name() == 'ssh-rsa'

    for key in keys:
        print('Trying ssh-agent key %s' % hexlify(key.get_fingerprint()))

    agent.close()


def test_signature(server):
    pass
