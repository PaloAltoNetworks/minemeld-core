from flask import g

import psutil  # noqa
import xmlrpclib
import supervisor.xmlrpc
import werkzeug.local

from . import config


__all__ = ['init_app', 'MMSupervisor']


def get_Supervisor():
    sserver = getattr(g, '_supervisor', None)
    if sserver is None:
        supervisorurl = config.get('SUPERVISOR_URL',
                                   'unix:///var/run/supervisor.sock')
        sserver = xmlrpclib.ServerProxy(
            'http://127.0.0.1',
            transport=supervisor.xmlrpc.SupervisorTransport(
                None,
                None,
                supervisorurl
            )
        )
        g._supervisor = sserver

    return sserver


MMSupervisor = werkzeug.local.LocalProxy(get_Supervisor)


def teardown(exception):
    SR = getattr(g, '_supervisor', None)
    if SR is not None:
        g._supervisor = None


def init_app(app):
    app.teardown_appcontext(teardown)
