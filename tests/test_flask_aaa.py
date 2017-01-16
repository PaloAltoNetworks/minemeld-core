#  Copyright 2016 Palo Alto Networks, Inc
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

"""FT autofocus tests

Unit tests for minemeld.ft.autofocus
"""

import gevent.monkey
gevent.monkey.patch_all(thread=False, select=False)

import unittest
import mock
import shutil
import logging
import os
import os.path
import base64
import passlib.apache
import xmltodict

os.environ['MM_CONFIG'] = '.'
os.environ['API_CONFIG_LOCK'] = os.path.join('.', 'api-config.lock')

import minemeld.flask.main
import minemeld.flask.feedredis

LOG = logging.getLogger(__name__)
MYDIR = os.path.dirname(__file__)
TAXII_POLL_REQUEST = """<taxii_11:Poll_Request 
    xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"
    message_id="42158"
    collection_name="%s">
    <taxii_11:Exclusive_Begin_Timestamp>2014-12-19T00:00:00Z</taxii_11:Exclusive_Begin_Timestamp>
    <taxii_11:Inclusive_End_Timestamp>2014-12-19T12:00:00Z</taxii_11:Inclusive_End_Timestamp>
    <taxii_11:Poll_Parameters allow_asynch="false">
        <taxii_11:Response_Type>FULL</taxii_11:Response_Type>
    </taxii_11:Poll_Parameters>
</taxii_11:Poll_Request>"""


def _authorization_header(username, password):
    return 'Basic '+base64.b64encode(username+':'+password)


class MineMeldFlaskAAATests(unittest.TestCase):
    def setUp(self):
        try:
            shutil.rmtree('./api')
        except OSError:
            pass

        os.mkdir('api')

        minemeld.flask.main.app.config.update(
            DEBUG=True
        )
        self.app = minemeld.flask.main.app.test_client()

    def tearDown(self):
        try:
            shutil.rmtree('./api')
        except OSError:
            pass

    def _taxii_discovery_request(self, username=None, password=None):
        headers = {
            'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
            'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0',
            'X-TAXII-Services': 'urn:taxii.mitre.org:services:1.1'
        }
        if username is not None:
            headers['Authorization'] = _authorization_header(username, password)
        resp = self.app.post(
            '/taxii-discovery-service',
            headers=headers,
            data='<Discovery_Request xmlns="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="1"/>'
        )

        return resp

    def _taxii_collection_request(self, username=None, password=None):
        headers = {
            'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
            'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0',
            'X-TAXII-Services': 'urn:taxii.mitre.org:services:1.1'
        }
        if username is not None:
            headers['Authorization'] = _authorization_header(username, password)
        resp = self.app.post(
            '/taxii-collection-management-service',
            headers=headers,
            data='<taxii_11:Collection_Information_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="26300"/>'
        )

        return resp

    def _taxii_poll_request(self, collection, username=None, password=None):
        headers = {
            'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
            'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0',
            'X-TAXII-Services': 'urn:taxii.mitre.org:services:1.1'
        }
        if username is not None:
            headers['Authorization'] = _authorization_header(username, password)
        resp = self.app.post(
            '/taxii-poll-service',
            headers=headers,
            data=TAXII_POLL_REQUEST % collection
        )

        return resp        

    def _num_collections(self, resp):
        ans = xmltodict.parse(resp.data)

        collections = ans['taxii_11:Collection_Information_Response']['taxii_11:Collection']
        if isinstance(collections, list):
            return len(collections)
        return 1

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_auth_disabled(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': False
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_single_tag(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_two_tags(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential', 'open']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_two_and_two(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential', 'open']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_any(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['any']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_anonymous(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['anonymous', 'confidential']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_anonymous_2(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['anonymous']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 200)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_no_tags(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {}
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_no_user_tags(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('guest', 'guest')
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('user1', 'password1')
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': _authorization_header('admin', 'password')
        })
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.feedredis.MMMaster')
    def test_feeds_malformed(self, mmmastermock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        mmmastermock.status.return_value = {
            'mbus:slave:feed1': {
                'class': 'minemeld.ft.redis.RedisSet'
            }
        }

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': 'invalid authorization'
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': 'Basic YWJjZGVmCg'
        })
        self.assertEqual(resp.status_code, 401)

        resp = self.app.get('/feeds/feed1', headers={
            'Authorization': 'Basic '+base64.b64encode('invalidauth')
        })
        self.assertEqual(resp.status_code, 401)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiidiscovery.get_taxii_feeds', return_value=['feed1'])
    @mock.patch('minemeld.flask.taxiicollmgmt.get_taxii_feeds', return_value=['feed1'])
    def test_taxii_auth_disabled(self, gtfmock1, gtfmock2, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': False,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_discovery_request()
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='guest', password='guest')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='admin', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request()
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='guest', password='guest')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='admin', password='password2')
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiidiscovery.get_taxii_feeds', return_value=['feed1', 'feed2'])
    @mock.patch('minemeld.flask.taxiicollmgmt.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxii_services_tag(self, gtfmock1, gtfmock2, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                },
                'feed2': {
                    'tags': ['disabled']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_discovery_request()
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_discovery_request(username='guest', password='guest')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_discovery_request(username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_discovery_request(username='admin', password='password1')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_collection_request()
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_collection_request(username='guest', password='guest')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_collection_request(username='user1', password='password1')
        self.assertEqual(self._num_collections(resp), 1)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='admin', password='password')
        self.assertEqual(self._num_collections(resp), 2)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_collection_request(username='admin', password='password2')
        self.assertEqual(resp.status_code, 401)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiidiscovery.get_taxii_feeds', return_value=['feed1', 'feed2'])
    @mock.patch('minemeld.flask.taxiicollmgmt.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxii_anonymous(self, gtfmock1, gtfmock2, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                },
                'feed2': {
                    'tags': ['anonymous']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_discovery_request()
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='guest', password='guest')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_discovery_request(username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='admin', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request()
        self.assertEqual(self._num_collections(resp), 1)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='guest', password='guest')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_collection_request(username='user1', password='password1')
        self.assertEqual(self._num_collections(resp), 1)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='admin', password='password')
        self.assertEqual(self._num_collections(resp), 2)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='admin', password='password2')
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiidiscovery.get_taxii_feeds', return_value=['feed1', 'feed2'])
    @mock.patch('minemeld.flask.taxiicollmgmt.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxii_any(self, gtfmock1, gtfmock2, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                },
                'feed2': {
                    'tags': ['any']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_discovery_request()
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_discovery_request(username='guest', password='guest')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_discovery_request(username='admin', password='password1')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_collection_request()
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_collection_request(username='guest', password='guest')
        self.assertEqual(self._num_collections(resp), 1)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='user1', password='password1')
        self.assertEqual(self._num_collections(resp), 2)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='admin', password='password')
        self.assertEqual(self._num_collections(resp), 2)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_collection_request(username='admin', password='password2')
        self.assertEqual(resp.status_code, 401)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiidiscovery.get_taxii_feeds', return_value=['feed1', 'feed2'])
    @mock.patch('minemeld.flask.taxiicollmgmt.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxii_any_anonymous(self, gtfmock1, gtfmock2, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                },
                'feed2': {
                    'tags': ['any', 'anonymous']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_discovery_request()
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='guest', password='guest')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_discovery_request(username='admin', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request()
        self.assertEqual(self._num_collections(resp), 1)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='guest', password='guest')
        self.assertEqual(self._num_collections(resp), 1)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='user1', password='password1')
        self.assertEqual(self._num_collections(resp), 2)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='admin', password='password')
        self.assertEqual(self._num_collections(resp), 2)
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='user1', password='password2')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_collection_request(username='admin', password='password2')
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiipoll.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxiipoll_single_tag(self, gtfmock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_poll_request('feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='guest', password='guest')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password2')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='admin', password='password1')
        self.assertEqual(resp.status_code, 401)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiipoll.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxiipolll_two_tags(self, gtfmock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential', 'open']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_poll_request('feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='guest', password='guest')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password2')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='admin', password='password1')
        self.assertEqual(resp.status_code, 401)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiipoll.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxiipoll_two_and_two(self, gtfmock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['confidential', 'open']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_poll_request('feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='guest', password='guest')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password2')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='admin', password='password1')
        self.assertEqual(resp.status_code, 401)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiipoll.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxiipoll_any(self, gtfmock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['any']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_poll_request('feed1')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='guest', password='guest')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password2')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='admin', password='password1')
        self.assertEqual(resp.status_code, 401)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiipoll.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxiipoll_anonymous(self, gtfmock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['anonymous', 'confidential']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_poll_request('feed1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='guest', password='guest')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='user1', password='password1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password2')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='admin', password='password1')
        self.assertEqual(resp.status_code, 200)

    @mock.patch.dict('minemeld.flask.config.os.environ', {
        'MM_CONFIG': '.',
        'API_CONFIG_LOCK': os.path.join('.', 'api-config.lock'),
    })
    @mock.patch('minemeld.flask.config.init')
    @mock.patch('minemeld.flask.config.get')
    @mock.patch('minemeld.flask.taxiipoll.get_taxii_feeds', return_value=['feed1', 'feed2'])
    def test_taxiipoll_anonymous_2(self, gtfmock, configmock, configinitmock):
        _config_attrs = {
            'API_AUTH_ENABLED': True,
            'USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'wsgi.htpasswd')),
            'FEEDS_USERS_DB': passlib.apache.HtpasswdFile(path=os.path.join(MYDIR, 'feeds.htpasswd')),
            'FEEDS_AUTH_ENABLED': True,
            'FEEDS_USERS_ATTRS': {
                'guest': {
                    'tags': ['open', 'test']
                },
                'user1': {
                    'tags': ['confidential']
                }
            },
            'FEEDS_ATTRS': {
                'feed1': {
                    'tags': ['anonymous']
                }
            }
        }

        def _config_get(attribute, default=None):
            if attribute in _config_attrs:
                return _config_attrs[attribute]
            return default

        configmock.configure_mock(side_effect=_config_get)

        resp = self._taxii_poll_request('feed1')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='guest', password='guest')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='user1', password='password1')
        self.assertEqual(resp.status_code, 401)

        resp = self._taxii_poll_request('feed1', username='admin', password='password')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='user1', password='password2')
        self.assertEqual(resp.status_code, 200)

        resp = self._taxii_poll_request('feed1', username='admin', password='password1')
        self.assertEqual(resp.status_code, 200)
