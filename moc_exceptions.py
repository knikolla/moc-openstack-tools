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


class InvalidEmailError(Exception):
    """User's email address does not pass basic format validation"""


class ItemExistsError(Exception):
    """Keystone resource already exists and cannot be created"""
    def __init__(self, item_type, item_name):
        msg = "{} exists with the name: {}".format(item_type, item_name)
        super(ItemExistsError, self).__init__(msg)


class ItemNotFoundError(Exception):
    """The specified Keystone resource was not found"""
    def __init__(self, item_type, item_name):
        msg = "No {} found in Keystone with name: {}".format(item_type,
                                                             item_name)
        super(ItemNotFoundError, self).__init__(msg)


class BadEmailRecipient(Exception):
    """If sending failed to one or more recipients, but not all of them."""
    def __init__(self, rdict, subject):
        self.__name__ = 'BadEmailRecipient'
        self.rejected = rdict
        self.message = ("Message '{0}' could not be sent to one or more "
                        "recipients.").format(subject)


class NoApprovedRequests(Exception):
    """No approved requests were found matching the given filter."""
    def __init__(self, row_filter):
        if not row_filter:
            row_filter = '--all'
        msg = ("No approved/ticketed requests found "
               "matching: {}").format(row_filter)
        super(NoApprovedRequests, self).__init__(msg)
