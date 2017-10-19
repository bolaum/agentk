import logging
import paramiko

logger = logging.getLogger(__name__)


def test_server_connection(server, key):
    agent = paramiko.Agent()
    keys = agent.get_keys()

    assert len(keys) == 1
    assert keys[0].get_name() == 'ssh-rsa'

    agent.close()


