import logging

from agentk import log
from agentk.server import Server
from agentk.kkmip_interface import KkmipInterface

logger = logging.getLogger(__name__)
log.setup(level='debug')


def agentk_main(args):
    logger.info('agentk starting...')

    logger.debug('connection to HSM...')
    kkmip = KkmipInterface('kryptus.dyndns.biz', 49252,
                           cert=('/home/bolaum/projs/desafiok/vhsm_12/user1.crt',
                                 '/home/bolaum/projs/desafiok/vhsm_12/user1.key'))


    logger.debug('starting server...')
    server = Server(kkmip)
    server.start()

    try:
        logger.debug('joining server...')
        server.join()
    except KeyboardInterrupt:
        server.close()
