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


def _list_metrics(prefix=None):
    result = os.listdir(RRD_PATH)

    if prefix is not None:
        result = [m for m in result if m.startswith(prefix)]

    return result


def _fetch_metric(cc, metric, type_=None, cf='MAX', dt=86400, r=1800):
    dirname = os.path.join(RRD_PATH, metric)

    if type_ is None:
        rrdname = os.listdir(dirname)[0]
    else:
        rrdname = type_+'.rrd'
        if rrdname not in os.listdir(dirname):
            raise RuntimeError('Unknown metric type')

    cc.flush(identifier='minemeld/%s/%s' % (metric, type_))

    (start, end, step), metrics, data = rrdtool.fetch(
        str(os.path.join(dirname, rrdname)),
        cf,
        '--start', '-%d' % dt,
        '--resolution', '%d' % r
    )

    result = []

    curts = start
    for v in data:
        result.append((curts, v[0]))
        curts += step

    return result


@app.route('/metrics/minemeld/<nodetype>')
@flask.ext.login.login_required
def get_node_type_metrics(nodetype):
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

    metrics = _list_metrics(prefix='minemeld.'+nodetype+'.')

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)

    result = []
    for m in metrics:
        v = _fetch_metric(cc, m, cf=cf, dt=dt, r=resolution)

        _, _, mname = m.split('.', 2)

        result.append({
            'metric': mname,
            'values': v
        })

    return jsonify(result=result)


@app.route('/metrics/minemeld')
@flask.ext.login.login_required
def get_global_metrics():
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

    metrics = _list_metrics(prefix='minemeld.')
    metrics = [m for m in metrics if 'minemeld.sources' not in m]
    metrics = [m for m in metrics if 'minemeld.outputs' not in m]
    metrics = [m for m in metrics if 'minemeld.transits' not in m]

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)

    result = []
    for m in metrics:
        v = _fetch_metric(cc, m, cf=cf, dt=dt, r=resolution)

        _, mname = m.split('.', 1)

        result.append({
            'metric': mname,
            'values': v
        })

    return jsonify(result=result)


@app.route('/metrics/<node>')
@flask.ext.login.login_required
def get_node_metrics(node):
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

    metrics = _list_metrics(prefix=node+'.')

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)

    result = []
    for m in metrics:
        v = _fetch_metric(cc, m, cf=cf, dt=dt, r=resolution)

        _, mname = m.split('.', 1)

        result.append({
            'metric': mname,
            'values': v
        })

    return jsonify(result=result)


@app.route('/metrics/<node>/<metric>', methods=['GET'])
@flask.ext.login.login_required
def get_metric(node, metric):
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

    metric = node+'.'+metric

    if metric not in _list_metrics():
        return jsonify(error={'message': 'Unknown metric'}), 404

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)

    try:
        result = _fetch_metric(cc, metric, type_=type_, cf=cf, dt=dt, r=r)
    except RuntimeError as e:
        return jsonify(error={'message': str(e)}), 400

    return jsonify(result=result)
