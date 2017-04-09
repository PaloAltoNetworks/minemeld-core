import logging
import json

from flask import current_app

# [2017-01-16 20:32:07 +0000] [15997] [INFO]
LOG_FORMAT = '[%(asctime)s] [%(process)d] [%(levelname)s] %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S %Z'


class MMLogger(object):
    def __init__(self):
        self.system_logger = logging.getLogger('minemeld')
        self._init_logger(self.system_logger)

        self.system_logger.info('MMLogger started')

    def init_app(self, app):
        del app.logger.handlers[:]

        self._init_logger(app.logger)

    def _init_logger(self, logger):
        logger.propagate = False
        logger.setLevel(logging.DEBUG)

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            fmt=LOG_FORMAT,
            datefmt=LOG_DATE_FORMAT
        ))
        logger.addHandler(handler)

    def debug(self, *args, **kwargs):
        if current_app:
            current_app.logger.debug(*args, **kwargs)
        else:
            self.system_logger.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        if current_app:
            current_app.logger.info(*args, **kwargs)
        else:
            self.system_logger.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        if current_app:
            current_app.logger.warning(*args, **kwargs)
        else:
            self.system_logger.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        if current_app:
            current_app.logger.error(*args, **kwargs)
        else:
            self.system_logger.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        if current_app:
            current_app.logger.critical(*args, **kwargs)
        else:
            self.system_logger.critical(*args, **kwargs)

    def exception(self, *args, **kwargs):
        if current_app:
            current_app.logger.exception(*args, **kwargs)
        else:
            self.system_logger.exception(*args, **kwargs)

    def audit(self, user_id, action_name, params, msg=None):
        audit_params = dict(user=user_id, action=action_name, params=params, msg=msg)
        self.info('AUDIT - {}'.format(json.dumps(audit_params)))


LOG = MMLogger()
