import logging
import os
import os.path

import rrdtool

from flask import request
from flask import jsonify

import flask.ext.login

import minemeld.collectd

from . import app
from . import config

LOG = logging.getLogger(__name__)
RRD_PATH = config.get('RRD_PATH', '/var/lib/collectd/rrd/minemeld/')
RRD_SOCKET_PATH = config.get('RRD_SOCKET_PATH', '/var/run/collectd.sock')
ALLOWED_CF = ['MAX', 'MIN', 'AVERAGE']


@app.route('/metrics', methods=['GET'])
@flask.ext.login.login_required
def get_metrics():
    result = os.listdir(RRD_PATH)
    return jsonify(result=result)


@app.route('/metrics/<metric>', methods=['GET'])
@flask.ext.login.login_required
def get_metric(metric):
    cf = str(request.args.get('cf', 'MAX')).upper()
    if cf not in ALLOWED_CF:
        return jsonify(error={'message': 'Unknown function'}), 400

    try:
        dt = int(request.args.get('dt', '86400'))
    except ValueError:
        return jsonify(error={'message': 'Invalid delta'}), 400
    if dt < 0:
        return jsonify(error={'message': 'Invalid delta'}), 400

    try:
        resolution = int(request.args.get('r', '1800'))
    except ValueError:
        return jsonify(error={'message': 'Invalid resolution'})
    if resolution < 0:
        return jsonify(error={'message': 'Invalid resolution'}), 400

    type_ = request.args.get('t', 'minemeld_counter')

    if metric not in os.listdir(RRD_PATH):
        return jsonify(error={'message': 'Unknown metric'}), 404

    dirname = os.path.join(RRD_PATH, metric)
    rrdname = type_+'.rrd'
    if rrdname not in os.listdir(dirname):
        return jsonify(error={'message': 'Unknown metric type'}), 400

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)
    cc.flush(identifier='minemeld/%s/%s' % (metric, type_))

    (start, end, step), metrics, data = rrdtool.fetch(
        str(os.path.join(dirname, rrdname)),
        cf,
        '--start', '-%d' % dt,
        '--resolution', '%d' % resolution
    )

    result = []

    curts = start
    for v in data:
        result.append((curts, v[0]))
        curts += step

    return jsonify(result=result)
