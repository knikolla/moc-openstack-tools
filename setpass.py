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
import string
import random


def random_password(size):
    """Generate a random password of length 'size'
    
    The resulting password may contain any of:
        upper or lowercase letters A-Z
        the digits 0-9
        valid punctuation marks defined in the 'punctuation' variable below
    """
    punctuation = '#$%&!'
    chars = string.ascii_letters + string.digits + punctuation
    return ''.join(random.choice(chars) for _ in range(size))


class SetpassClient:
    """Class for interacting with a Setpass server"""
    def __init__(self, session, setpass_url):
        self.url = setpass_url
        self.session = session
    
    def get_token(self, userid, password, pin):
        """Add the user ID and random password to the setpass database.
        
        Returns a token allowing the user to set their password.
        """
        body = {'password': password, 'pin': pin}
        request_url = '{base}/token/{userid}'.format(base=self.url,
                                                     userid=userid)
        response = self.session.put(request_url, json=body)
        token = response.text
        return token

    def get_url(self, token):
        """ Generate URL for the user to set their password """
        url = "{base}?token={token}".format(base=self.url, token=token)
        return url
