"""FT syslog tests

Unit tests for minemeld.ft.syslog
"""

import unittest
import shutil
import time
import logging
import mock
import gevent
import gc

import minemeld.ft.syslog

FTNAME = 'testft-%d' % int(time.time())

LOG = logging.getLogger(__name__)


class MineMeldFTSyslogMatcherests(unittest.TestCase):
    def setUp(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

        try:
            shutil.rmtree(FTNAME+"_ipv4")
        except:
            pass

        try:
            shutil.rmtree(FTNAME+"_indicators")
        except:
            pass

    def tearDown(self):
        try:
            shutil.rmtree(FTNAME)
        except:
            pass

        try:
            shutil.rmtree(FTNAME+"_ipv4")
        except:
            pass

        try:
            shutil.rmtree(FTNAME+"_indicators")
        except:
            pass

    @mock.patch.object(gevent, 'spawn_later')
    def test_handle_ip(self, spawnl_mock):
        config = {
        }

        chassis = mock.Mock()

        ochannel = mock.Mock()
        chassis.request_pub_channel.return_value = ochannel

        rpcmock = mock.Mock()
        rpcmock.get.return_value = {'error': None, 'result': 'OK'}
        chassis.send_rpc.return_value = rpcmock

        a = minemeld.ft.syslog.SyslogMatcher(FTNAME, chassis, config)

        inputs = ['a']
        output = True

        a.connect(inputs, output)
        a.mgmtbus_initialize()
        a.start()
        self.assertEqual(spawnl_mock.call_count, 1)

        a.update('a', indicator='1.1.1.1-1.1.1.2', value={
            'type': 'IPv4',
            'confidence': 100
        })
        self.assertEqual(a.length(), 1)

        a._handle_ip('1.1.1.1')
        self.assertEqual(a.table.num_indicators, 1)
        self.assertEqual(ochannel.publish.call_count, 1)

        a.stop()
        a.table.db.close()
        a.table_ipv4.db.close()
        a.table_indicators.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()
