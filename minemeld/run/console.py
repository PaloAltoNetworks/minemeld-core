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

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import logging
import signal
import time
import uuid
import json

import click

import minemeld.comm
import minemeld.mgmtbus
import minemeld.traced

LOG = logging.getLogger(__name__)


def _send_cmd(ctx, target, command, params=None, source=True):
    if params is None:
        params = {}

    if source:
        params['source'] = ctx.obj['SOURCE']
    return ctx.obj['COMM'].send_rpc(
        target,
        command,
        params
    )


def _print_json(obj):
    print json.dumps(
        obj,
        indent=4,
        sort_keys=True
    )


@click.group()
@click.option('--comm-class', default='ZMQRedis',
              metavar='CLASSNAME')
@click.option('--verbose', count=True)
@click.pass_context
def cli(ctx, verbose, comm_class):
    comm_class = str(comm_class)
    source = 'console-%d' % int(time.time())

    loglevel = logging.WARNING
    if verbose > 0:
        loglevel = logging.INFO
    if verbose > 1:
        loglevel = logging.DEBUG
    logging.basicConfig(
        level=loglevel,
        format="%(asctime)s (%(process)d)%(module)s.%(funcName)s"
               " %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )

    comm = minemeld.comm.factory(comm_class, {})  # XXX should support config

    gevent.signal(signal.SIGTERM, comm.stop)
    gevent.signal(signal.SIGQUIT, comm.stop)
    gevent.signal(signal.SIGINT, comm.stop)

    comm.start()

    ctx.obj['COMM'] = comm
    ctx.obj['SOURCE'] = source


@cli.command()
@click.argument('target')
@click.pass_context
def length(ctx, target):
    if target is None:
        raise click.UsageError(message='target required')

    _print_json(_send_cmd(ctx, target, 'length'))

    ctx.obj['COMM'].stop()


@cli.command()
@click.argument('target')
@click.pass_context
def hup(ctx, target):
    if target is None:
        raise click.UsageError(message='target required')

    target = 'mbus:directslave:'+target
    _print_json(_send_cmd(ctx, target, 'hup'))

    ctx.obj['COMM'].stop()


@cli.command()
@click.argument('target', required=False, default=None)
@click.pass_context
def status(ctx, target):
    if target is None:
        target = minemeld.mgmtbus.MGMTBUS_MASTER
    else:
        target = 'mbus:directslave:'+target

    _print_json(_send_cmd(ctx, target, 'status', source=False))

    ctx.obj['COMM'].stop()


@cli.command(name='signal')
@click.argument('signal')
@click.argument('target')
@click.pass_context
def mm_signal(ctx, signal, target):
    target = 'mbus:directslave:'+target
    _print_json(_send_cmd(ctx, target, 'signal', source=False, params={'signal': signal}))

    ctx.obj['COMM'].stop()


# XXX query should subscribe to the Redis topic to dump the
# query results
@cli.command()
@click.argument('query')
@click.option('--from-counter', default=None, type=int)
@click.option('--from-timestamp', default=None, type=int)
@click.option('--num-lines', default=100, type=int)
@click.option('--query-uuid', default=None)
@click.pass_context
def query(ctx, query, from_counter, from_timestamp, num_lines, query_uuid):
    if query_uuid is None:
        query_uuid = str(uuid.uuid4())

    _print_json(
        _send_cmd(
            ctx,
            minemeld.traced.QUERY_QUEUE,
            'query',
            source=False,
            params={
                'uuid': query_uuid,
                'timestamp': from_timestamp,
                'counter': from_counter,
                'num_lines': num_lines,
                'query': query
            }
        )
    )

    ctx.obj['COMM'].stop()


def main():
    cli(obj={})  # pylint:disable=E1123,E1120
