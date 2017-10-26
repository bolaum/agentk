import logging
import logging.handlers
import logging.config
from colorlog import ColoredFormatter

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}


class TimeFormatter(ColoredFormatter):
    def format(self, record):
        record.adjustedTime = record.relativeCreated / 1000.0
        return ColoredFormatter.format(self, record)


def setup(level='info'):
    logging.getLogger('sarge').setLevel(logging.ERROR)

    formatter = TimeFormatter(
        '%(green)s[%(adjustedTime)12.6f]%(reset)s '
        '%(blue)s%(name)16s:%(funcName)16s():%(lineno)3d:%(reset)s'
        '%(log_color)s[%(levelname)5s]%(reset)s: %(message)s',
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        },
        secondary_log_colors={},
        style='%'
    )

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logging.root.addHandler(ch)
    logging.root.setLevel(LEVELS.get(level.lower(), logging.INFO))
