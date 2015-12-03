import os
import yaml

CONFIG = {}

_config_path = os.environ.get('MM_CONFIG', None)

if _config_path is not None:
    with open(_config_path, 'r') as f:
        CONFIG = yaml.safe_load(f)

get = CONFIG.get
