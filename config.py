#   Copyright 2016 Massachusetts Open Cloud
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
"""Centralized configuration setup"""
from os import path


def set_config_file(cfg_file=None):
    """Return the absolute path of the specified or default config file"""

    if cfg_file is not None:
        if path.isfile(cfg_file):
            CONFIG = cfg_file
        else:
            msg = "Config file does not exist: '{}'".format(cfg_file)
            raise IOError(msg)

    else:
        default_cfg_file = path.join(path.dirname(path.abspath(__file__)),
                                     'settings.ini')
        if path.isfile(default_cfg_file):
            CONFIG = default_cfg_file
        else:
            raise IOError("No valid configuration files found.")

    return CONFIG
