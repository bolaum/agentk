import logging

from agentk import log
from agentk.server import Server
from agentk.kkmip_interface import KkmipInterface

import warnings
warnings.filterwarnings("ignore")

logger = logging.getLogger(__name__)



def agentk_main(options):
    logger.debug(options)

    level = 'error'
    if options.v:
        level = 'info'

    if options.d:
        level = 'debug'

    log.setup(level=level)

    logger.info('agentk starting...')

    kkmip = KkmipInterface(options.host, options.port, cert=(options.cert, options.key))

    try:
        kkmip.ping_hsm()
    except Exception as e:
        logger.error('Error pinging HSM: %s', e)
        exit(1)

    logger.info('Starting server...')
    server = Server(kkmip, sock_fn=options.socket_file)

    server.start()

    print('SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;' % options.socket_file)

    try:
        logger.debug('Joining server...')
        server.join()
    except KeyboardInterrupt:
        server.close()
