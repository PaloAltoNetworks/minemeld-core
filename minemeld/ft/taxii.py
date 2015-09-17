import requests
import logging
import copy
import gevent
import gevent.event
import random
import urlparse
import datetime
import pytz
import lxml.etree

import libtaxii
import libtaxii.clients
import libtaxii.messages_11

import stix.core.stix_package

from . import base
from . import table
from . import ft_states
from .utils import utc_millisec
from .utils import RWLock

LOG = logging.getLogger(__name__)


class TaxiiClient(base.BaseFT):
    def __init__(self, name, chassis, config):
        self.glet = None

        self.active_requests = []
        self.rebuild_flag = False
        self.last_run = None
        self.idle_waitobject = gevent.event.AsyncResult()

        self.poll_service = None
        self.collection_mgmt_service = None

        self.emit_lock = RWLock()

        super(TaxiiClient, self).__init__(name, chassis, config)

    def configure(self):
        super(TaxiiClient, self).configure()

        self.source_name = self.config.get('source_name', self.name)
        self.discovery_service = self.config.get('discovery_service', None)
        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)
        self.collection = self.config.get('collection', None)
        self.attributes = self.config.get('attributes', {})
        self.interval = self.config.get('interval', 900)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.num_retries = self.config.get('num_retries', 2)

    def _initialize_table(self, truncate=False):
        self.table = table.Table(self.name, truncate=truncate)
        self.table.create_index('last_seen')

    def initialize(self):
        self._initialize_table()

    def rebuild(self):
        self.rebuild_flag = True
        self._initialize_table()

    def reset(self):
        self._initialize_table(truncate=True)

    def _build_taxii_client(self):
        result = libtaxii.clients.HttpClient()

        up = urlparse.urlparse(self.discovery_service)

        if up.scheme == 'https':
            result.set_use_https(True)

        if self.username and self.password:
            result.set_auth_type(libtaxii.clients.HttpClient.AUTH_BASIC)
            result.set_auth_credentials({
                'username': self.username,
                'password': self.password
            })

        return result

    def _discover_services(self, tc):
        msg_id = libtaxii.messages_11.generate_message_id()
        request = libtaxii.messages_11.DiscoveryRequest(msg_id)
        request = request.to_xml()

        up = urlparse.urlparse(self.discovery_service)
        hostname = up.hostname
        path = up.path

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request
        )

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('Discovery_Response {%s} %s',
                  type(tm), tm.to_xml(pretty_print=True))

        self.collection_mgmt_service = None
        for si in tm.service_instances:
            if si.service_type != libtaxii.constants.SVC_COLLECTION_MANAGEMENT:
                continue

            self.collection_mgmt_service = si.service_address
            break

        if self.collection_mgmt_service is None:
            raise RuntimeError('%s - collection management service not found')

        LOG.debug('%s - collection_mgmt_service: %s',
                  self.name, self.collection_mgmt_service)

    def _check_collections(self, tc):
        msg_id = libtaxii.messages_11.generate_message_id()
        request = libtaxii.messages_11.CollectionInformationRequest(msg_id)
        request = request.to_xml()

        up = urlparse.urlparse(self.collection_mgmt_service)
        hostname = up.hostname
        path = up.path

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request
        )

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('Collection_Information_Response {%s} %s',
                  type(tm), tm.to_xml(pretty_print=True))

        tci = None
        for ci in tm.collection_informations:
            if ci.collection_name != self.collection:
                continue

            tci = ci
            break

        if tci is None:
            raise RuntimeError('%s - collection %s not found',
                               self.name, self.collection)

        if tci.polling_service_instances is None or \
           len(tci.polling_service_instances) == 0:
           raise RuntimeError('%s - collection %s doesn\'t support polling',
                              self.name, self.collection)

        if tci.collection_type != libtaxii.constants.CT_DATA_FEED:
            raise RuntimeError('%s - collection %s is not a data feed (%s)',
                               self.name, self.collection, tci.collection_type)

        self.poll_service = tci.polling_service_instances[0].poll_address

        LOG.debug('%s - poll service: %s',
                  self.name, self.poll_service)

    def _poll_fulfillment_request(self, result_id, result_part_number):
        msg_id = libtaxii.messages_11.generate_message_id()
        request = libtaxii.messages_11.PollFulfillmentRequest(
            message_id=msg_id,
            result_id=result_id,
            result_part_number=result_part_number,
            collection_name=self.collection
        )
        request = request.to_xml()

        up = urlparse.urlparse(self.poll_service)
        hostname = up.hostname
        path = up.path

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request
        )

        return libtaxii.get_message_from_http_response(resp, msg_id)

    def _poll_collection(self, tc, begin=None, end=None):
        msg_id = libtaxii.messages_11.generate_message_id()
        pps = libtaxii.messages_11.PollParameters(
            response_type='FULL',
            allow_asynch=False
        )
        request = libtaxii.messages_11.PollRequest(
            message_id=msg_id,
            collection_name=self.collection,
            exclusive_begin_timestamp_label=begin,
            inclusive_end_timestamp_label=end,
            poll_parameters=pps
        )

        LOG.debug('%s - first poll request %s',
                  self.name, request.to_xml(pretty_print=True))

        request = request.to_xml()

        up = urlparse.urlparse(self.poll_service)
        hostname = up.hostname
        path = up.path

        resp = tc.call_taxii_service2(
            hostname,
            path,
            libtaxii.constants.VID_TAXII_XML_11,
            request
        )

        tm = libtaxii.get_message_from_http_response(resp, msg_id)

        LOG.debug('%s - Poll_Response {%s} %s',
                  self.name, type(tm), tm.to_xml(pretty_print=True))

        self._handle_content_blocks(tm.content_blocks)

        while tm.more:
            tm = self._poll_fulfillment_request(
                result_id=tm.result_id,
                result_part_number=tm.result_part_number+1
            )
            self._handle_content_blocks(tm.content_blocks)

    def _handle_content_blocks(self, content_blocks):
        for cb in content_blocks:
            if cb.content_binding.binding_id != \
                libtaxii.constants.CB_STIX_XML_111:
                LOG.error('%s - Unsupported contenti binding: %s',
                          self.name, cb.content_binding.binding_id)
                continue


            stixpackage = stix.core.stix_package.STIXPackage.from_xml(
                lxml.etree.fromstring(cb.content)
            )

            LOG.debug('observables: %s', stixpackage.observables)

    def _run(self):
        if self.rebuild_flag:
            LOG.debug("rebuild flag set, resending current indicators")
            # reinit flag is set, emit update for all the known indicators
            for i, v in self.table.query('last_seen', include_value=True):
                self.emit_update(i, v)

        tc = self._build_taxii_client()

        while True:
            try:
                self._discover_services(tc)
                self._check_collections(tc)

                while True:
                    now = utc_millisec()

                    last_run = self.last_run
                    if last_run is None:
                        last_run = now-86400000

                    begin = datetime.datetime.fromtimestamp(last_run/1000)
                    begin = begin.replace(tzinfo=pytz.UTC)

                    end = datetime.datetime.fromtimestamp(now/1000)
                    end = end.replace(tzinfo=pytz.UTC)

                    self._poll_collection(
                        tc,
                        begin=begin,
                        end=end
                    )

                    self.last_run = now

                    gevent.sleep(self.interval)

            except gevent.GreenletExit:
                break

            except:
                LOG.exception('%s - exception in main loop', self.name)
                gevent.sleep(300)

    def mgmtbus_status(self):
        result = super(TaxiiClient, self).mgmtbus_status()
        result['last_run'] = self.last_run

        return result

    def length(self, source=None):
        return self.table.num_indicators

    def start(self):
        super(TaxiiClient, self).start()

        if self.glet is not None:
            return

        self.glet = gevent.spawn_later(random.randint(0, 2), self._run)

    def stop(self):
        super(TaxiiClient, self).stop()

        if self.glet is None:
            return

        for g in self.active_requests:
            g.kill()

        self.glet.kill()

        LOG.info("%s - # indicators: %d", self.name, self.table.num_indicators)
