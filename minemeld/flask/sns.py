import requests
import json
import os.path
import uuid
import minemeld
from .logger import LOG
from . import config

SNSAPIURL = config.get('SNS_URL', 'https://o11kiw0vpe.execute-api.us-east-1.amazonaws.com/run')
SNSENABLED = config.get('SNS_ENABLED', False)
UUIDFILENAME = config.get('UUID_FILE', 'uu.id4')
TYPEHELLO = 'hello'
TYPEMKWISH = 'mkwish'
TYPESTATS = 'stats'

sns_obj = {}
sns_available = False


class sns:
    def __init__(self, path):
        self.api_url = SNSAPIURL
        self.filename = os.path.join(path, UUIDFILENAME)
        self.mm_version = minemeld.__version__
        self.init_ok = self._init_uuid()

    def get_status(self):
        return self.init_ok

    def _init_uuid(self):
        uuid_error = uuid.UUID(bytes='\x01' * 16).hex
        # Test case 1: UUIDFILENAME file does not exist. We try to create a new uuid and store in the filesystem
        if not os.path.isfile(self.filename):
            self.uuid = uuid.uuid4().hex
            # If we've failed to send the one-in-a-lifetime hello we just don't store the uuid to try again next boot
            if self._hello_world():
                try:
                    with open(self.filename, 'w') as f:
                        f.write(self.uuid)
                        LOG.debug('New uuid file created.')
                except Exception as e:
                    # Let the caller know uuid was not saved meaning sns might not be ready
                    LOG.debug('Something went wrong creating the uuid file: {}'.format(self.filename))
                except Exception:
                    return False
                LOG.debug('Instance uuid = {}'.format(self.uuid))
                LOG.debug('MineMeld cloud notification service is ready.')
                return True
            LOG.info('MineMeld cloud notification service is not available.')
            return False
        # Test case 2: UUIDFILENAME exists but we can't open it (permissions issues?)
        try:
            f = open(self.filename)
        except IOError:
            self.uuid = uuid_error
            LOG.info('Failure opening the uuid file {}'.format(self.filename))
            return True
        r_uuid = f.readline().strip()
        f.close()
        # Test case 3: We can read UUIDFILENAME but the content is not a valid UUID4
        try:
            val = uuid.UUID(r_uuid, version=4)
        except ValueError:
            self.uuid = uuid_error
            LOG.info('Invalid uuid value in the file: {}'.format(r_uuid))
            return True
        self.uuid = val.hex if val.hex == r_uuid else uuid_error
        LOG.debug('Instance uuid = {}'.format(self.uuid))
        return True

    def _send_message(self, kvmessage):
        kvmessage['uuid'] = self.uuid
        kvmessage['version'] = self.mm_version
        try:
            r = requests.post(self.api_url,
                              data=json.dumps(kvmessage),
                              timeout=5,
                              headers={'Content-Type': 'application/json'})
        except Exception as e:
            return False
        if r.status_code == requests.codes.ok:
            response = r.json()
            if response.get('response', '') == 'ok':
                return True
        return False

    def _hello_world(self):
        return self._send_message({'type': TYPEHELLO, 'message': 'Hello world!'})

    def make_wish(self, message):
        LOG.debug('Sending new wish message to SNS')
        return self._send_message({'type': TYPEMKWISH, 'message': message})

    def send_stats(self, stats):
        stats['type'] = TYPESTATS
        return self._send_message(stats)


def init_app():
    global sns_obj
    global sns_available
    if not SNSENABLED:
        return
    sns_obj = sns(config.API_CONFIG_PATH)
    sns_available = sns_obj.get_status()
