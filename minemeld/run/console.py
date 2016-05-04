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
import pprint
import uuid

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


class FakeNode(object):
    def update(self, source=None, indicator=None, value=None):
        print 'source:', source
        print 'indicator:', indicator
        print 'value: %s' % value
        print


@click.group()
@click.option('--comm-class', default='AMQP',
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
    comm.request_rpc_server_channel(
        source,
        FakeNode(),
        allowed_methods=['update']
    )

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

    print _send_cmd(ctx, target, 'length')

    ctx.obj['COMM'].stop()


@cli.command()
@click.argument('target')
@click.pass_context
def hup(ctx, target):
    if target is None:
        raise click.UsageError(message='target required')

    print _send_cmd(ctx, target, 'hup')

    ctx.obj['COMM'].stop()


@cli.command()
@click.argument('target')
@click.argument('indicator')
@click.pass_context
def get(ctx, target, indicator):
    if target is None:
        raise click.UsageError(message='target required')
    if indicator is None:
        raise click.UsageError(message='indicator required')

    print _send_cmd(ctx, target, 'get', params={'value': indicator})

    ctx.obj['COMM'].stop()


@cli.command()
@click.argument('target')
@click.pass_context
def get_all(ctx, target):
    if target is None:
        raise click.UsageError(message='target required')

    print _send_cmd(ctx, target, 'get_all')

    ctx.obj['COMM'].stop()


@cli.command()
@click.argument('target')
@click.option('--index')
@click.option('--from-key')
@click.option('--to-key')
@click.pass_context
def get_range(ctx, target, index, from_key, to_key):
    if target is None:
        raise click.UsageError(message='target required')

    print _send_cmd(ctx, target, 'get_all_range', params={
        'index': index,
        'from_key': from_key,
        'to_key': to_key
    })

    ctx.obj['COMM'].stop()


@cli.command()
@click.pass_context
def status(ctx):
    pprint.pprint(_send_cmd(ctx, minemeld.mgmtbus.MGMTBUS_MASTER,
                            'status', source=False))

    ctx.obj['COMM'].stop()


# XXX query should subscribe to the Redis topic to dump the 
# query results
@cli.command()
@click.argument('query')
@click.option('--from-counter', default=None, type=int)
@click.option('--from-timestamp', default=None, type=int)
@click.option('--num-lines', default=100, type=int)
@click.pass_context
def query(ctx, query, from_counter, from_timestamp, num_lines):
    pprint.pprint(_send_cmd(ctx, minemeld.traced.QUERY_QUEUE,
                            'query', source=False, params={
                                'uuid': str(uuid.uuid4()),
                                'timestamp': from_timestamp,
                                'counter': from_counter,
                                'num_lines': num_lines,
                                'query': query
                            }))

    ctx.obj['COMM'].stop()


def main():
    cli(obj={})
