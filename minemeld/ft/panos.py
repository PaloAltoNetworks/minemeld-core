import logging
import gevent
import gevent.event
import minemeld.packages.panforest

from . import base
from . import table
from .utils import utc_millisec

LOG = logging.getLogger(__name__)


class PanOSLogsAPIFT(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.glet = None

        self.table = table.Table(name)
        self.table.create_index('_updated')
        self.active_requests = []
        self.rebuild_flag = False
        self.last_log = None
        self.idle_waitobject = gevent.event.AsyncResult()

        super(PanOSLogsAPIFT, super).__init__(self, name, chassis, config)

    def configure(self):
        super(HttpFT, self).configure()

        self.source_name = self.config.get('source_name', self.name)
        self.tag = self.config.get('tag', None)
        self.hostname = self.config.get('hostname', None)
        self.api_key = self.config.get('api_key', None)
        self.api_username = self.config.get('api_username', None)
        self.api_password = self.config.get('api_password', None)
        self.log_type = self.config.get('log_type', None)
        self.filter = self.config.get('filter', None)

    def rebuild(self):
        self.rebuild_flag = True

    def reset(self):
        self.table.close()

        self.table = table.Table(self.name, truncate=True)
        self.table.create_index('_updated')

    def emit_checkpoint(self, value):
        LOG.debug("%s - checkpoint set to %s", self.name, value)
        self.idle_waitobject.set(value)

    def _run(self):
        if self.rebuild_flag:
            LOG.debug("rebuild flag set, resending current indicators")
            # reinit flag is set, emit update for all the known indicators
            for i, v in self.table.query('_updated', include_value=True):
                self.emit_update(i, v)

        while True:
            try:
                xapi = pan.xapi.PanXapi(
                    api_username=self.api_username,
                    api_password=self.api_password,
                    api_key=self.api_key,
                    hostname=self.hostname,
                    tag=self.tag,
                    timeout=60
                )
                pf = minemeld.packages.panforest.PanForest(
                    xapi=xapi,
                    log_type=self.log_type,
                    filter=self.filter,
                    format='xml'
                )

                for log in pf.follow():
                    LOG.debug('log %s', log)
            except:
                LOG.exception("%s - exception in log loop")

    def start(self):
        super(PanOSLogsAPIFT, self).start()

        if self.glet is not None:
            return

        self.glet = gevent.spawn_later(random.randint(0, 2), self._run)

    def stop(self):
        super(PanOSLogsAPIFT, self).stop()

        if self.glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.glet.kill()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
