#!/usr/bin/env python

import gevent
import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import logging
import signal
import uuid

import click

import minemeld.chassis

LOG = logging.getLogger(__name__)


@click.group()
@click.option('--fabric-class', default='minemeld.fabric.AMQP',
              metavar='CLASSNAME')
@click.option('--verbose', count=True)
@click.pass_context
def cli(ctx, verbose, fabric_class):
    fabric_class = str(fabric_class)

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

    ftname = str(uuid.uuid4())

    c = minemeld.chassis.Chassis(
        fabric_class,
        {},
        report_state=False
    )

    c.configure({
        ftname: {
            'class': 'minemeld.ft.inspect.InspectFT',
            'args': {}
        }
    })

    gevent.signal(signal.SIGTERM, c.stop)
    gevent.signal(signal.SIGQUIT, c.stop)
    gevent.signal(signal.SIGINT, c.stop)

    c.start()
    ft = c.get_ft(ftname)

    ctx.obj['CHASSIS'] = c
    ctx.obj['FTNAME'] = ftname
    ctx.obj['FT'] = ft


@cli.command()
@click.argument('target')
@click.pass_context
def length(ctx, target):
    if target is None:
        raise click.UsageError(message='target required')

    try:
        ctx.obj['FT'].call_length(target=target)
    except gevent.timeout.Timeout:
        print 'Timeout'

    ctx.obj['CHASSIS'].stop()


@cli.command()
@click.argument('target')
@click.argument('indicator')
@click.pass_context
def get(ctx, target, indicator):
    if target is None:
        raise click.UsageError(message='target required')
    if indicator is None:
        raise click.UsageError(message='indicator required')

    try:
        ctx.obj['FT'].call_get(target=target, indicator=indicator)
    except gevent.timeout.Timeout:
        print 'Timeout'

    ctx.obj['CHASSIS'].stop()


@cli.command()
@click.argument('target')
@click.pass_context
def get_all(ctx, target):
    if target is None:
        raise click.UsageError(message='target required')

    try:
        ctx.obj['FT'].call_get_all(target=target)
    except gevent.timeout.Timeout:
        print 'Timeout'

    ctx.obj['CHASSIS'].stop()


@cli.command()
@click.argument('target')
@click.option('--index')
@click.option('--from-key')
@click.option('--to-key')
@click.pass_context
def get_range(ctx, target, index, from_key, to_key):
    if target is None:
        raise click.UsageError(message='target required')

    try:
        ctx.obj['FT'].call_get_range(target=target, index=index,
                                     from_key=from_key, to_key=to_key)
    except gevent.timeout.Timeout:
        print 'Timeout'

    ctx.obj['CHASSIS'].stop()


if __name__ == "__main__":
    cli(obj={})
