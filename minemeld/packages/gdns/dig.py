# Based on resolver_ares.py from gevent
# Copyright (c) 2011 Denis Bilenko. See LICENSE for details.

from __future__ import absolute_import
import os
from _socket import gaierror
from gevent.hub import Waiter, get_hub
from minemeld.packages.gdns._ares import channel


class Dig(object):

    ares_class = channel

    # from arpa/nameser.h
    NS_C_INVALID = 0  # Cookie
    NS_C_IN = 1  # Internet
    NS_C_2 = 2  # unallocated/unsupported
    NS_C_CHAOS = 3  # MIT Chaos-net
    NS_C_HS = 4  # MIT Hesiod
    NS_C_NONE = 254  # prereq. sections in update requests
    NS_C_ANY = 255  # Wildcard match
    NS_C_MAX = 65536

    NS_T_INVALID = 0  # Cookie
    NS_T_A = 1  # Host address
    NS_T_NS = 2  # Authoritative server
    NS_T_MD = 3  # Mail destination
    NS_T_MF = 4  # Mail forwarder
    NS_T_CNAME = 5  # Canonical name
    NS_T_SOA = 6  # Start of authority zone
    NS_T_MB = 7  # Mailbox domain name
    NS_T_MG = 8  # Mail group member
    NS_T_MR = 9  # Mail rename name
    NS_T_NULL = 10  # Null resource record
    NS_T_WKS = 11  # Well known service
    NS_T_PTR = 12  # Domain name pointer
    NS_T_HINFO = 13  # Host information
    NS_T_MINFO = 14  # Mailbox information
    NS_T_MX = 15  # Mail routing information
    NS_T_TXT = 16  # Text strings
    NS_T_RP = 17  # Responsible person
    NS_T_AFSDB = 18  # AFS cell database
    NS_T_X25 = 19  # X_25 calling address
    NS_T_ISDN = 20  # ISDN calling address
    NS_T_RT = 21  # Router
    NS_T_NSAP = 22  # NSAP address
    NS_T_NSAP_PTR = 23  # Reverse NSAP lookup (deprecated)
    NS_T_SIG = 24  # Security signature
    NS_T_KEY = 25  # Security key
    NS_T_PX = 26  # X.400 mail mapping
    NS_T_GPOS = 27  # Geographical position (withdrawn)
    NS_T_AAAA = 28  # Ip6 Address
    NS_T_LOC = 29  # Location Information
    NS_T_NXT = 30  # Next domain (security)
    NS_T_EID = 31  # Endpoint identifier
    NS_T_NIMLOC = 32  # Nimrod Locator
    NS_T_SRV = 33  # Server Selection
    NS_T_ATMA = 34  # ATM Address
    NS_T_NAPTR = 35  # Naming Authority PoinTeR
    NS_T_KX = 36  # Key Exchange
    NS_T_CERT = 37  # Certification record
    NS_T_A6 = 38  # IPv6 address (deprecated, use NS_T_AAAA)
    NS_T_DNAME = 39  # Non-terminal DNAME (for IPv6)
    NS_T_SINK = 40  # Kitchen sink (experimentatl)
    NS_T_OPT = 41  # EDNS0 option (meta-RR)
    NS_T_APL = 42  # Address prefix list (RFC3123)
    NS_T_TKEY = 249  # Transaction key
    NS_T_TSIG = 250  # Transaction signature
    NS_T_IXFR = 251  # Incremental zone transfer
    NS_T_AXFR = 252  # Transfer zone of authority
    NS_T_MAILB = 253  # Transfer mailbox records
    NS_T_MAILA = 254  # Transfer mail agent records
    NS_T_ANY = 255  # Wildcard match
    NS_T_ZXFR = 256  # BIND-specific, nonstandard
    NS_T_MAX = 65536

    def __init__(self, hub=None, **kwargs):
        if hub is None:
            hub = get_hub()
        self.hub = hub

        self.ares = self.ares_class(hub.loop, **kwargs)
        self.pid = os.getpid()
        self.params = kwargs
        self.fork_watcher = hub.loop.fork(ref=False)
        self.fork_watcher.start(self._on_fork)

    def __repr__(self):
        return (
            '<minemeld.packages.gdns.dig.Dig at 0x%x ares=%r>' %
            (id(self), self.ares)
        )

    def _on_fork(self):
        pid = os.getpid()
        if pid != self.pid:
            self.hub.loop.run_callback(self.ares.destroy)
            self.ares = self.ares_class(self.hub.loop, **self.params)
            self.pid = pid

    def close(self):
        if self.ares is not None:
            self.hub.loop.run_callback(self.ares.destroy)
            self.ares = None
        self.fork_watcher.stop()

    def query(self, name, dnsclass, type_):
        if isinstance(name, unicode):
            name = name.encode('ascii')
        elif not isinstance(name, str):
            raise TypeError('Expected string, not %s' % type(name).__name__)

        while True:
            ares = self.ares
            try:
                waiter = Waiter(self.hub)
                ares.query(waiter, name, dnsclass, type_)
                result = waiter.get()

                return result

            except gaierror:
                if ares is self.ares:
                    raise

    def parse_txt_reply(self, reply):
        return self.ares.parse_txt_reply(reply)
