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

import os
import os.path
import hashlib

import rrdtool

from flask import request, jsonify

import minemeld.collectd

from . import config
from .aaa import MMBlueprint
from .logger import LOG


__all__ = ['BLUEPRINT']


RRD_PATH = config.get('RRD_PATH', '/var/lib/collectd/rrd/minemeld/')
RRD_SOCKET_PATH = config.get('RRD_SOCKET_PATH', '/var/run/collectd.sock')
ALLOWED_CF = ['MAX', 'MIN', 'AVERAGE']


BLUEPRINT = MMBlueprint('metrics', __name__, url_prefix='/metrics')


def _list_metrics(prefix=None):
    result = os.listdir(RRD_PATH)

    if prefix is not None:
        result = [m for m in result if m.startswith(prefix)]

    return result


def _fetch_metric(cc, metric, type_=None,
                  cf='MAX', dt=86400, r=1800):
    dirname = os.path.join(RRD_PATH, metric)

    if type_ is None:
        rrdname = os.listdir(dirname)[0]
        type_ = rrdname.replace('.rrd', '')
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

    if type_ != 'minemeld_delta':
        curts = start
        for v in data:
            result.append([curts, v[0]])
            curts += step
    else:
        curts = start+step
        ov = data[0][0]
        for v in data[1:]:
            cv = v[0]
            if cv is not None and ov is not None:
                if cv >= ov:
                    cv = cv - ov
            result.append([curts, cv])

            ov = v[0]
            curts += step

    return result


@BLUEPRINT.route('/', read_write=False)
def get_metrics():
    return jsonify(result=_list_metrics())


@BLUEPRINT.route('/minemeld/<nodetype>', read_write=False)
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
        return jsonify(error={'message': 'Invalid resolution'}), 400
    if resolution < 0:
        return jsonify(error={'message': 'Invalid resolution'}), 400

    type_ = request.args.get('t', None)

    metrics = _list_metrics(prefix='minemeld.'+nodetype+'.')

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)

    result = []
    for m in metrics:
        v = _fetch_metric(cc, m, cf=cf, dt=dt, r=resolution, type_=type_)

        _, _, mname = m.split('.', 2)

        result.append({
            'metric': mname,
            'values': v
        })

    return jsonify(result=result)


@BLUEPRINT.route('/minemeld', read_write=False)
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
        return jsonify(error={'message': 'Invalid resolution'}), 400
    if resolution < 0:
        return jsonify(error={'message': 'Invalid resolution'}), 400

    type_ = request.args.get('t', None)

    metrics = _list_metrics(prefix='minemeld.')
    metrics = [m for m in metrics if 'minemeld.sources' not in m]
    metrics = [m for m in metrics if 'minemeld.outputs' not in m]
    metrics = [m for m in metrics if 'minemeld.transits' not in m]

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)

    result = []
    for m in metrics:
        v = _fetch_metric(cc, m, cf=cf, dt=dt, r=resolution, type_=type_)

        _, mname = m.split('.', 1)

        result.append({
            'metric': mname,
            'values': v
        })

    return jsonify(result=result)


@BLUEPRINT.route('/<node>', read_write=False)
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
        return jsonify(error={'message': 'Invalid resolution'}), 400
    if resolution < 0:
        return jsonify(error={'message': 'Invalid resolution'}), 400

    type_ = request.args.get('t', None)

    node = hashlib.md5(node).hexdigest()[:10]
    metrics = _list_metrics(prefix=node+'.')

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)

    result = []
    for m in metrics:
        v = _fetch_metric(cc, m, cf=cf, dt=dt, r=resolution, type_=type_)

        _, mname = m.split('.', 1)

        result.append({
            'metric': mname,
            'values': v
        })

    return jsonify(result=result)


@BLUEPRINT.route('/<node>/<metric>', methods=['GET'], read_write=False)
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
        return jsonify(error={'message': 'Invalid resolution'}), 400
    if resolution < 0:
        return jsonify(error={'message': 'Invalid resolution'}), 400

    type_ = request.args.get('t', 'minemeld_counter')

    node = hashlib.md5(node).hexdigest()[:10]
    metric = node+'.'+metric

    if metric not in _list_metrics():
        return jsonify(error={'message': 'Unknown metric'}), 404

    cc = minemeld.collectd.CollectdClient(RRD_SOCKET_PATH)

    try:
        result = _fetch_metric(cc, metric, type_=type_, cf=cf,
                               dt=dt, r=resolution)
    except RuntimeError as e:
        return jsonify(error={'message': str(e)}), 400

    return jsonify(result=result)
