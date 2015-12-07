import logging

import psutil
import time
import gevent
import xmlrpclib
import supervisor.xmlrpc

from flask import jsonify

import flask.ext.login

from . import app
from . import config
from . import MMSupervisor

LOG = logging.getLogger(__name__)


def _restart_engine():
    LOG.info('Restarting minemeld-engine')

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

    result = sserver.supervisor.stopProcess('minemeld-engine', False)
    if not result:
        LOG.error('Stop minemeld-engine returned False')
        return
    LOG.info('Stopped minemeld-engine for API request')

    now = time.time()
    info = None
    while (time.time()-now) < 60*15*1000:
        info = sserver.supervisor.getProcessInfo('minemeld-engine')
        if info['statename'] == 'STOPPED':
            break
        gevent.sleep(5)

    if info is not None and info['statename'] != 'STOPPED':
        LOG.error('Timeout during minemeld-engine restart')
        return

    sserver.supervisor.startProcess('minemeld-engine', False)
    LOG.info('Started minemeld-engine')


@app.route('/supervisor', methods=['GET'])
@flask.ext.login.login_required
def service_status():
    try:
        supervisorstate = MMSupervisor.supervisor.getState()

    except:
        LOG.exception("Exception connecting to supervisor")
        return jsonify(result={'statename': 'STOPPED'})

    supervisorstate['processes'] = {}
    pinfo = MMSupervisor.supervisor.getAllProcessInfo()
    for p in pinfo:
        process = {
            'statename': p['statename'],
            'start': p['start']
        }

        try:
            ps = psutil.Process(pid=p['pid'])
            process['children'] = len(ps.children())

        except:
            LOG.exception("Error retrieving childen of %d" % p['pid'])
            pass

        supervisorstate['processes'][p['name']] = process

    return jsonify(result=supervisorstate)


@app.route('/supervisor/minemeld-engine/start', methods=['GET'])
@flask.ext.login.login_required
def start_minemeld_engine():
    result = MMSupervisor.supervisor.startProcess('minemeld-engine', False)

    return jsonify(result=result)


@app.route('/supervisor/minemeld-engine/stop', methods=['GET'])
@flask.ext.login.login_required
def stop_minemeld_engine():
    result = MMSupervisor.supervisor.stopProcess('minemeld-engine', False)

    return jsonify(result=result)


@app.route('/supervisor/minemeld-engine/restart', methods=['GET'])
@flask.ext.login.login_required
def restart_minemeld_engine():
    info = MMSupervisor.supervisor.getProcessInfo('minemeld-engine')
    if info['statename'] != 'RUNNING':
        return jsonify(error={
            'message': ('minemeld-engine not in RUNNING state: %s' %
                        info['statename'])
        }), 400

    gevent.spawn(_restart_engine)

    return jsonify(result='OK')
