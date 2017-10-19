import os
from pytest import fixture
from time import sleep

from agentk.server import Server
from agentk import log

log.setup('debug')

SOCK_FILE = 'agentk.sock'


@fixture(scope='session')
def server():
    os.environ["SSH_AUTH_SOCK"] = os.path.abspath('agentk.sock')

    if os.path.exists(SOCK_FILE):
        os.remove(SOCK_FILE)

    server = Server(sock_fn=SOCK_FILE)
    server.start()
    sleep(1)

    yield server

    server.close()
