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


def check_for_rpc(call_args_list, check_list, all_here=False):
    LOG.debug("call_args_list: %s", call_args_list)

    found = []
    for chk in check_list:
        LOG.debug("checking: %s", chk)

        for j in xrange(len(call_args_list)):
            if j in found:
                continue

            args = call_args_list[j][0]

            if args[0] != chk['method']:
                continue
            if args[1]['indicator'] != chk['indicator']:
                continue

            chkvalue = chk.get('value', None)
            if chkvalue is None:
                found.append(j)
                LOG.debug("found @%d", j)
                break

            argsvalue = args[1].get('value', None)
            if chkvalue is not None and argsvalue is None:
                continue

            failed = False
            for k in chkvalue.keys():
                if k not in argsvalue:
                    failed = True
                    break
                if chkvalue[k] != argsvalue[k]:
                    failed = True
                    break
            if failed:
                continue

            found.append(j)
            LOG.debug("found @%d", j)
            break

    c1 = len(found) == len(check_list)

    if not all_here:
        return c1

    c2 = len(found) == len(call_args_list)

    return c1+c2 == 2


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
    def test_handle_ip_01(self, spawnl_mock):
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
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': '1.1.1.1',
                        'value': {
                            'syslog_original_indicator':
                                'IPv4'+'1.1.1.1-1.1.1.2',
                            'type': 'IPv4',
                            'confidence': 100
                        }
                    }
                ],
                all_here=True
            )
        )

        a.stop()
        a.table.db.close()
        a.table_ipv4.db.close()
        a.table_indicators.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn_later')
    def test_handle_ip_02(self, spawnl_mock):
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

        a.update('a', indicator='1.1.1.1-1.1.1.2', value={
            'type': 'IPv4',
            'confidence': 100
        })
        a._handle_ip('1.1.1.1')

        ochannel.publish.reset_mock()
        a.withdraw('a', indicator='1.1.1.1-1.1.1.2')
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'withdraw',
                        'indicator': '1.1.1.1'
                    }
                ],
                all_here=True
            )
        )

        a.stop()
        a.table.db.close()
        a.table_ipv4.db.close()
        a.table_indicators.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn_later')
    def test_handle_url_01(self, spawnl_mock):
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

        a.update('a', indicator='www.example.com', value={
            'type': 'domain',
            'confidence': 100
        })
        self.assertEqual(a.length(), 1)

        a._handle_url('www.example.com/cgi/addressbook.php')
        self.assertEqual(a.table.num_indicators, 1)
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'update',
                        'indicator': 'www.example.com',
                        'value': {
                            'syslog_original_indicator':
                                'domain'+'www.example.com',
                            'type': 'domain',
                            'confidence': 100
                        }
                    }
                ],
                all_here=True
            )
        )

        a.stop()
        a.table.db.close()
        a.table_ipv4.db.close()
        a.table_indicators.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()

    @mock.patch.object(gevent, 'spawn_later')
    def test_handle_url_02(self, spawnl_mock):
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

        a.update('a', indicator='www.example.com', value={
            'type': 'domain',
            'confidence': 100
        })
        a._handle_url('www.example.com/cgi/addressbook.php')

        ochannel.publish.reset_mock()
        a.withdraw('a', indicator='www.example.com')
        self.assertEqual(a.table_indicators.num_indicators, 0)
        self.assertTrue(
            check_for_rpc(
                ochannel.publish.call_args_list,
                [
                    {
                        'method': 'withdraw',
                        'indicator': 'www.example.com'
                    }
                ],
                all_here=True
            )
        )

        a.stop()
        a.table.db.close()
        a.table_ipv4.db.close()
        a.table_indicators.db.close()

        a = None
        chassis = None
        rpcmock = None
        ochannel = None

        gc.collect()
