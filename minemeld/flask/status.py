import logging

import psutil
import os
import yaml

from flask import Response
from flask import stream_with_context
from flask import jsonify

import flask.ext.login

from . import app
from . import MMMaster
from . import MMStateFanout

LOG = logging.getLogger(__name__)


def stream_events():
    sid = MMStateFanout.subscribe()

    try:
        while True:
            yield MMStateFanout.get(sid)

    except GeneratorExit:
        MMStateFanout.unsubscribe(sid)

    except:
        LOG.exception("Exception stream_events")
        MMStateFanout.unsubscribe(sid)


# @app.route('/status/events', methods=['GET'])
# @flask.ext.login.login_required
def get_events():
    r = Response(stream_with_context(stream_events()),
                 mimetype="text/event-stream")
    return r


@app.route('/status/system', methods=['GET'])
@flask.ext.login.login_required
def get_system_status():
    res = {}
    res['cpu'] = psutil.cpu_percent(interval=1, percpu=True)
    res['memory'] = psutil.virtual_memory().percent
    res['swap'] = psutil.swap_memory().percent
    res['disk'] = psutil.disk_usage('/').percent

    return jsonify(result=res)


@app.route('/status/minemeld', methods=['GET'])
@flask.ext.login.login_required
def get_minemeld_status():
    status = MMMaster.status()

    tr = status.get('result', None)
    if tr is None:
        return jsonify(error={'message': status.get('error', 'error')})

    result = []
    for f, v in tr.iteritems():
        LOG.debug(f)
        _, _, v['name'] = f.split(':', 2)
        result.append(v)

    return jsonify(result=result)


@app.route('/status/config', methods=['GET'])
@flask.ext.login.login_required
def get_minemeld_running_config():
    rcpath = os.path.join(
        os.path.dirname(os.environ.get('MM_CONFIG')),
        'running-config.yml'
    )
    with open(rcpath, 'r') as f:
        rcconfig = yaml.safe_load(f)

    return jsonify(result=rcconfig)
