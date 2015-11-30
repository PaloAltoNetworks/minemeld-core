import logging

import os
import psutil

from flask import Response
from flask import jsonify

import flask.ext.login

from . import app
from . import MMSupervisor

LOG = logging.getLogger(__name__)


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
            'statename': p['statename']
        }

        try:
            ps = psutil.Process(pid=p['pid'])
            process['children'] = len(ps.children())

        except:
            LOG.exception("Error retrieving childen of %d" % p['pid'])
            pass

        supervisorstate['processes'][p['name']] = process

    return jsonify(result=supervisorstate)

@app.route('/supervisor/minemeld-core/start', methods=['GET'])
@flask.ext.login.login_required
def start_minemeld_core():
    result = MMSupervisor.supervisor.startProcess('minemeld-core', False)

    return jsonify(result=result)

@app.route('/supervisor/minemeld-core/stop', methods=['GET'])
@flask.ext.login.login_required
def stop_minemeld_core():
    result = MMSupervisor.supervisor.stopProcess('minemeld-core', False)

    return jsonify(result=result)
