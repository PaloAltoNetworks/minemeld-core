"""gevent_openssl - gevent compatibility with pyOpenSSL.

Usage
-----

Instead of importing OpenSSL directly, do so in the following manner:

..

    import gevent_openssl as OpenSSL

or

..

    import gevent_openssl; gevent_openssl.monkey_patch()

Any calls that would have blocked the current thread will now only block the
current green thread.

This compatibility is accomplished by ensuring the nonblocking flag is
set before any blocking operation and the OpenSSL file descriptor is
polled internally to trigger needed events.
"""

from . import SSL as MySSL
from OpenSSL import *


def monkey_patch():
    """
    Monkey patches `OpenSSL.SSL.Connection`
    """
    mod = __import__('OpenSSL').SSL
    mod.Connection = MySSL.Connection
