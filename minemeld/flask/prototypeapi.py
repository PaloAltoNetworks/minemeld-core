import logging

import os
import yaml

import flask.ext.login

from flask import jsonify

from . import app

LOG = logging.getLogger(__name__)

PROTOTYPE_ENV = 'MINEMELD_PROTOTYPE_PATH'


@app.route('/prototype', methods=['GET'])
@flask.ext.login.login_required
def list_prototypes():
    paths = os.getenv(PROTOTYPE_ENV, None)
    if paths is None:
        raise RuntimeError('%s environment variable not set' %
                           (PROTOTYPE_ENV))
    paths = paths.split(':')

    prototypes = {}
    for p in paths:
        try:
            for plibrary in os.listdir(p):
                if not plibrary.endswith('.yml'):
                    continue

                plibraryname, _ = plibrary.rsplit('.', 1)

                with open(os.path.join(p, plibrary), 'r') as f:
                    pcontents = yaml.safe_load(f)

                prototypes[plibraryname] = pcontents

        except:
            LOG.exception('Error loading libraries from %s', p)

    return jsonify(result=prototypes)
