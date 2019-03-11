#!/usr/bin/env python2

import logging
import time
import urllib
import os
import sys
import re

from itertools import izip_longest

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG = logging.getLogger(__name__)


def get_full_config(mmurl, username, password):
    response = requests.get(
        '{}/config/full'.format(mmurl),
        auth=(username, password),
        verify=False
    )
    response.raise_for_status()

    return response.json()['result']


def delete_node(nodeid, version, mmurl, username, password):
    response = requests.delete(
        '{}/config/node/{}'.format(mmurl, nodeid),
        params={'version': version},
        auth=(username, password),
        verify=False
    )
    response.raise_for_status()


def create_node(version, nodename, prototype, inputs, output, mmurl, username, password):
    response = requests.post(
        '{}/config/node'.format(mmurl),
        auth=(username, password),
        verify=False,
        json={
            'name': nodename,
            'version': version,
            'properties': {
                'prototype': prototype,
                'inputs': inputs,
                'output': output
            }
        },
        headers={
            'Content-Type': 'application/json'
        }
    )
    response.raise_for_status()


def commit_and_restart(mmurl, username, password):
    full_config = get_full_config(mmurl, username, password)

    response = requests.post(
        '{}/config/commit'.format(mmurl),
        auth=(username, password),
        verify=False,
        json={
            'version': full_config['version'],
        },
        headers={
            'Content-Type': 'application/json'
        }
    )
    response.raise_for_status()

    response = requests.get(
        '{}/supervisor/minemeld-engine/restart'.format(mmurl),
        auth=(username, password),
        verify=False
    )
    response.raise_for_status()


def delete_config(mmurl, username, password):
    LOG.info('Deleting config...')

    full_config = get_full_config(mmurl, username, password)

    for idx, n in enumerate(full_config['nodes']):
        if not n:
            continue
        
        delete_node(
            idx,
            n['version'],
            mmurl,
            username,
            password
        )

    full_config = get_full_config(mmurl, username, password)
    nnodes = len([n for n in full_config['nodes'] if n])
    if nnodes != 0:
        raise RuntimeError('Config not deleted: {!r}'.format(full_config))


def create_config(mmurl, username, password):
    LOG.info('Creating new config...')

    full_config = get_full_config(mmurl, username, password)

    # miner
    create_node(
        version=full_config['version'],
        nodename='localdb',
        prototype='stdlib.localDB',
        output=True,
        inputs=[],
        mmurl=mmurl,
        username=username,
        password=password
    )

    # URL flow
    create_node(
        version=full_config['version'],
        nodename='URLAggregator',
        prototype='stdlib.aggregatorURL',
        output=True,
        inputs=['localdb'],
        mmurl=mmurl,
        username=username,
        password=password
    )
    create_node(
        version=full_config['version'],
        nodename='URLHC',
        prototype='stdlib.feedHCWithValue',
        output=True,
        inputs=['URLAggregator'],
        mmurl=mmurl,
        username=username,
        password=password
    )

    # domain flow
    create_node(
        version=full_config['version'],
        nodename='DomainAggregator',
        prototype='stdlib.aggregatorDomain',
        output=True,
        inputs=['localdb'],
        mmurl=mmurl,
        username=username,
        password=password
    )
    create_node(
        version=full_config['version'],
        nodename='DomainHC',
        prototype='stdlib.feedHCWithValue',
        output=True,
        inputs=['DomainAggregator'],
        mmurl=mmurl,
        username=username,
        password=password
    )

    # IPv4
    create_node(
        version=full_config['version'],
        nodename='IPv4Aggregator',
        prototype='stdlib.aggregatorIPv4Generic',
        output=True,
        inputs=['localdb'],
        mmurl=mmurl,
        username=username,
        password=password
    )
    create_node(
        version=full_config['version'],
        nodename='IPv4HC',
        prototype='stdlib.feedHCWithValue',
        output=True,
        inputs=['IPv4Aggregator'],
        mmurl=mmurl,
        username=username,
        password=password
    )


def wait_for_restart(mmurl, username, password):
    LOG.info('Waiting for restart...')

    now = time.time()

    while time.time() < (now + 300):
        response = requests.get(
            '{}/supervisor'.format(mmurl),
            auth=(username, password),
            verify=False
        )
        response.raise_for_status()

        supervisor_status = response.json()['result']
        engine_status = supervisor_status['processes']['minemeld-engine']['statename']

        if engine_status == 'RUNNING':
            break

        time.sleep(10)

    else:
        raise RuntimeError('engine did not restart in 5 minutes')

def push_indicators(mmurl, username, password):
    LOG.info('Pushing indicators...')

    with open('IPv4.lst', 'r') as f:
        ipv4_iocs = f.readlines()

    with open('URL.lst', 'r') as f:
        url_iocs = f.readlines()

    with open('domain.lst', 'r') as f:
        domain_iocs = f.readlines()

    num_ipv4_iocs = len(ipv4_iocs)
    ipv4_iocs = ['IPv4\n{}\n\n'.format(ioc) for ioc in ipv4_iocs]

    num_url_iocs = len(url_iocs)
    url_iocs = ['URL\n{}\n\n'.format(ioc) for ioc in url_iocs]

    num_domain_iocs = len(domain_iocs)
    domain_iocs = ['domain\n{}\n\n'.format(ioc) for ioc in domain_iocs]

    response = requests.post(
        '{}/config/data/localdb_indicators/append'.format(mmurl),
        params={
            'h': 'localdb',
            't': 'localdb'
        },
        auth=(username, password),
        headers={'Content-Type': 'application/text'},
        data=''.join(ipv4_iocs)+''.join(url_iocs)+''.join(domain_iocs),
        verify=False
    )
    response.raise_for_status()

    # wait for URLs to propagate
    LOG.info('Waiting for URLs to propagate...')
    now = time.time()
    while time.time() < (now + 300):
        response = requests.get(
            '{}/feeds/URLHC'.format(mmurl),
            verify=False
        )
        response.raise_for_status()

        if len(response.content.splitlines()) == num_url_iocs:
            break
    
        time.sleep(10)

    else:
        raise RuntimeError('URL IOCs did not propagate in 5 minutes')

    # wait for IPv4s to propagate
    LOG.info('Waiting for IPv4s to propagate...')
    now = time.time()
    while time.time() < (now + 300):
        response = requests.get(
            '{}/feeds/IPv4HC'.format(mmurl),
            verify=False
        )
        response.raise_for_status()

        if len(response.content.splitlines()) == num_ipv4_iocs:
            break
    
        time.sleep(10)

    else:
        raise RuntimeError('IPv4 IOCs did not propagate in 5 minutes')

    # wait for domains to propagate
    LOG.info('Waiting for domains to propagate...')
    now = time.time()
    while time.time() < (now + 300):
        response = requests.get(
            '{}/feeds/DomainHC'.format(mmurl),
            verify=False
        )
        response.raise_for_status()

        if len(response.content.splitlines()) == num_domain_iocs:
            break

        time.sleep(10)
    
    else:
        raise RuntimeError('domain IOCs did not propagate in 5 minutes')


def remove_timestamps(s):
    s = re.sub(r'\"first_seen\":[0-9]+', '\"first_seen\":0', s)
    s = re.sub(r'\"last_seen\":[0-9]+', '\"last_seen\":0', s)
    s = re.sub(r'\"timestamp\": [0-9]+', '\"timestamp\": 0', s)

    return s


def check_feeds(mmurl):
    check_result = True

    local_files = os.listdir('.')

    for fname in local_files:
        if not fname.endswith('.result'):
            continue

        req, _ = fname.split('.', 1)

        with open(fname, 'r') as f:
            result = f.readlines()

        LOG.info('Checking {}...'.format(urllib.unquote(req)))
        response = requests.get(
            '{}/feeds/{}'.format(mmurl, urllib.unquote(req)),
            verify=False
        )
        response.raise_for_status()

        clines = response.content.splitlines()

        for idx, (cl, rl) in enumerate(izip_longest(result, clines)):
            cl = remove_timestamps(cl.strip())
            rl = remove_timestamps(rl.strip())

            if cl != rl:
                LOG.error('{} does not match'.format(urllib.unquote(req)))
                LOG.error('L{}    expected: {!r}'.format(idx, rl))
                LOG.error('L{}    result:   {!r}'.format(idx, cl))
                
                check_result = False
                break

    return check_result

def main():
    logging.basicConfig(level=logging.INFO)

    mmurl = os.environ.get('MM_URL', 'https://127.0.0.1')
    username = os.environ.get('MM_USERNAME', 'admin')
    password = os.environ.get('MM_PASSWORD', 'minemeld')

    delete_config(mmurl, username, password)
    commit_and_restart(mmurl, username, password)
    wait_for_restart(mmurl, username, password)

    create_config(mmurl, username, password)
    commit_and_restart(mmurl, username, password)
    wait_for_restart(mmurl, username, password)

    push_indicators(mmurl, username, password)

    if not check_feeds(mmurl):
        sys.exit(1)


if __name__ == '__main__':
    main()
