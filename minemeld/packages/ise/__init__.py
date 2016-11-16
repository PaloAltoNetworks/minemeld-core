import logging

DEBUG1 = logging.DEBUG
DEBUG2 = DEBUG1 - 1
DEBUG3 = DEBUG2 - 1

logging.addLevelName(DEBUG2, 'DEBUG2')
logging.addLevelName(DEBUG3, 'DEBUG3')
