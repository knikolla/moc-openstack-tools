#   Copyright 2017 Massachusetts Open Cloud
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
"""Utility functions shared by multiple modules"""
from os import path


def get_absolute_path(file_path):
    """Convert a possibly relative file path to an absolute file path"""
    if not path.isabs(file_path):
        this_dir = path.dirname(path.abspath(__file__))
        abs_path = path.abspath(path.join(this_dir, file_path))
        return abs_path
    else:
        return file_path
