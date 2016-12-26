import logging
from collections import namedtuple

import gevent
from gevent.queue import Queue

from minemeld.ft.base import BaseFT, _counting


LOG = logging.getLogger(__name__)

ActorCommand = namedtuple('ActorCommand', ['commnad', 'kwargs_'])


class ActorBaseFT(BaseFT):
    def __init__(self, *args, **kwargs):
        super(ActorBaseFT, self).__init__(*args, **kwargs)

        self._actor_queue = Queue(maxsize=1)
        self._actor_glet = None

    @_counting('rebuild.queued')
    def command_rebuild(self):
        pass

    @_counting('checkpoint.queued')
    def checkpoint(self, **kwargs):
        self._actor_queue.put(ActorCommand(commnad='checkpoint', kwargs_=kwargs))

    @_counting('update.queued')
    def update(self, **kwargs):
        self._actor_queue.put(ActorCommand(commnad='update', kwargs_=kwargs))

    @_counting('withdraw.queued')
    def withdraw(self, **kwargs):
        self._actor_queue.put(ActorCommand(commnad='withdraw', kwargs_=kwargs))

    def _actor_loop(self):
        while True:
            acommand = self._actor_queue.get()

            if acommand.commnad == 'checkpoint':
                method = super(ActorBaseFT, self).checkpoint
            elif acommand.commnad == 'update':
                method = super(ActorBaseFT, self).update
            elif acommand.commnad == 'withdraw':
                method = super(ActorBaseFT, self).withdraw
            elif acommand.command == 'rebuild':
                method = self._rebuild
            else:
                LOG.error('{} - unknown command {}'.format(self.name, acommand.command))

            try:
                method(**acommand.kwargs_)
            except gevent.GreenletExit:
                break
            except:
                LOG.exception('{} - error executing {!r}'.format(self.name, acommand))

    def start(self):
        super(ActorBaseFT, self).start()

        if self._actor_glet is not None:
            return

        self._actor_glet = gevent.spawn(self._actor_loop)

    def stop(self):
        super(ActorBaseFT, self).stop()

        if self._actor_glet is None:
            return

        self._actor_glet.kill()
        self._actor_glet = None
