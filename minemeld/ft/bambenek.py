"""
This module implements a thin wrapper class around minemeld.ft.csv.CSVFT
to mine Bambenek Consulting feeds
"""

from __future__ import absolute_import

import logging

from . import csv

LOG = logging.getLogger(__name__)


class Miner(csv.CSVFT):
    pass
