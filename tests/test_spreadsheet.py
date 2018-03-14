#   Copyright 2018 Massachusetts Open Cloud
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

import os
import mock

# This is a hack for now until directory structure is sorted
# When this is removed remember to un-ignore E402 in flake8
import sys
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(TEST_DIR, os.pardir))
sys.path.insert(0, PROJECT_DIR)

from spreadsheet import Spreadsheet


def test_group_index():
    assert Spreadsheet._group_index([]) == []
    assert Spreadsheet._group_index([1]) == [[1, 2]]
    assert Spreadsheet._group_index([1, 2]) == [[1,3]]
    assert Spreadsheet._group_index([1, 2, 5]) == [[1, 3], [5, 6]]
    assert Spreadsheet._group_index(
        [1, 2, 3, 12, 13, 8, 6]
    ) == [[1, 4], [6, 7], [8, 9], [12, 14]]
