import logging
import paramiko

logger = logging.getLogger(__name__)


def test_server_connection(server):
    agent = paramiko.Agent()
    agent.get_keys()

