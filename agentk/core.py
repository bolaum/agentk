import logging

from agentk import log
from agentk.server import Server
from agentk.kkmip_interface import KkmipInterface

logger = logging.getLogger(__name__)
log.setup(level='debug')


def agentk_main(args):
    logger.info('agentk starting...')

    logger.debug('connection to HSM...')
    kkmip = KkmipInterface()


    logger.debug('starting server...')
    server = Server()
    server.start()

    try:
        logger.debug('joining server...')
        server.join()
    except KeyboardInterrupt:
        server.close()
