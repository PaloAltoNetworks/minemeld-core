#  Copyright 2015 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import logging

import psutil
import time
import gevent
import xmlrpclib
import supervisor.xmlrpc

from flask import jsonify, Blueprint
from flask.ext.login import login_required

from . import config
from .supervisorclient import MMSupervisor


__all__ = ['BLUEPRINT']


LOG = logging.getLogger(__name__)

BLUEPRINT = Blueprint('supervisor', __name__, url_prefix='')


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

    try:
        result = sserver.supervisor.stopProcess('minemeld-engine', False)
        if not result:
            LOG.error('Stop minemeld-engine returned False')
            return

    except xmlrpclib.Fault as e:
        LOG.error('Error stopping minemeld-engine: {!r}'.format(e))

    LOG.info('Stopped minemeld-engine for API request')

    now = time.time()
    info = None
    while (time.time()-now) < 60*10*1000:
        info = sserver.supervisor.getProcessInfo('minemeld-engine')
        if info['statename'] in ('FATAL', 'STOPPED', 'UNKNOWN', 'EXITED'):
            break
        gevent.sleep(5)
    else:
        LOG.error('Timeout during minemeld-engine restart')
        return

    sserver.supervisor.startProcess('minemeld-engine', False)
    LOG.info('Started minemeld-engine')


@BLUEPRINT.route('/supervisor', methods=['GET'])
@login_required
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


@BLUEPRINT.route('/supervisor/minemeld-engine/start', methods=['GET'])
@login_required
def start_minemeld_engine():
    result = MMSupervisor.supervisor.startProcess('minemeld-engine', False)

    return jsonify(result=result)


@BLUEPRINT.route('/supervisor/minemeld-engine/stop', methods=['GET'])
@login_required
def stop_minemeld_engine():
    result = MMSupervisor.supervisor.stopProcess('minemeld-engine', False)

    return jsonify(result=result)


@BLUEPRINT.route('/supervisor/minemeld-engine/restart', methods=['GET'])
@login_required
def restart_minemeld_engine():
    info = MMSupervisor.supervisor.getProcessInfo('minemeld-engine')
    if info['statename'] == 'STARTING' or info['statename'] == 'STOPPING':
        return jsonify(error={
            'message': ('minemeld-engine not in RUNNING state: %s' %
                        info['statename'])
        }), 400

    gevent.spawn(_restart_engine)

    return jsonify(result='OK')
