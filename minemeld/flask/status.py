import logging

import psutil

from flask import Response
from flask import stream_with_context
from flask import jsonify

from . import app
from . import MWStateFanout

LOG = logging.getLogger(__name__)


def stream_events():
    sid = MWStateFanout.subscribe()

    try:
        while True:
            yield MWStateFanout.get(sid)

    except GeneratorExit:
        MWStateFanout.unsubscribe(sid)

    except:
        LOG.exception("Exception stream_events")
        MWStateFanout.unsubscribe(sid)


@app.route('/status/events', methods=['GET'])
def get_events():
    r = Response(stream_with_context(stream_events()),
                 mimetype="text/event-stream")
    return r


@app.route('/status/system', methods=['GET'])
def get_system_status():
    res = {}
    res['cpu'] = psutil.cpu_percent(interval=1, percpu=True)
    res['memory'] = psutil.virtual_memory().percent
    res['swap'] = psutil.swap_memory().percent
    res['disk'] = psutil.disk_usage('/').percent

    return jsonify(result=res)
