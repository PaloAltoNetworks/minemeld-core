#!/usr/bin/env python

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import logging
import signal
import time

import click

import minemeld.comm

LOG = logging.getLogger(__name__)


def _send_cmd(ctx, target, command, params={}):
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


if __name__ == "__main__":
    cli(obj={})
