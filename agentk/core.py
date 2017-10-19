import logging

from agentk import log
from agentk.server import Server

logger = logging.getLogger(__name__)
log.setup(level='debug')


def agentk_main(args):
    logger.info('agentk starting...')

    logger.debug('starting server...')
    server = Server()
    server.start()

    try:
        logger.debug('joining server...')
        server.join()
    except KeyboardInterrupt:
        server.close()
