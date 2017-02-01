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
"""Script allowing a new user to reset their password securely.  

Th script performs the following  actions:
    - Resets the user's OpenStack password to a random string
    - Add the user, new password, and PIN to the Setpass service
    - Generates a Setpass link the user will visit to reset their password
    - Send the link via email to the user 

Usage:
    python reset-password.py <username> <PIN>

The PIN must be a 4-digit number and the user must provide it to successfully
set their new password. 

For more information on the Setpass service see:
https://github.com/CCI-MOC/setpass 
"""
import sys
import string
import random
import re
import argparse
import ConfigParser
from keystoneclient.v3 import client

#setpass
from keystoneauth1.identity import v3
from keystoneauth1 import session

#local import
from message import TemplateMessage

CONFIG_FILE = "settings.ini"

config = ConfigParser.ConfigParser()
config.read(CONFIG_FILE)

admin_user = config.get('auth', 'admin_user')
admin_pwd = config.get('auth', 'admin_pwd')
auth_url = config.get('setpass', 'keystone_v3_url')
setpass_url = config.get('setpass', 'setpass_url')

def random_password(size):
    chars = string.ascii_letters + string.digits + string.punctuation[2:6]
    return ''.join(random.choice(chars) for _ in range(size))

class Setpass:
    def __init__(self, keystone_v3_url, keystone_admin, keystone_password, setpass_url):
        self.url = setpass_url
        auth = v3.Password(auth_url=keystone_v3_url,
                           username=keystone_admin,
                           user_domain_id = 'default',
                           password=keystone_password)
        self.session = session.Session(auth=auth)
    
    def get_token(self, userid, password, pin):
        """ Add the user ID and random password to the setpass database.  
        
        Returns a token allowing the user to set their password.
        """
        body = { 'password': password, 'pin': pin }
        request_url = '{base}/token/{userid}'.format(base=self.url, userid=userid)
        response = self.session.put(request_url, json=body)
        token = response.text
        return token

    def get_url(self, token):
        """ Generate URL for the user to set their password """
        url = "{base}?token={token}".format(base=self.url, token=token)
        return url


def validate_pin(pin):
    """Check that PIN is 4 digits"""
    if not re.match('^([0-9]){4}$', pin):
        msg = "'{}' is not a valid four-digit PIN".format(pin)
        raise argparse.ArgumentTypeError(msg)
    else:
        return pin

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Reset an existing user's password")
    parser.add_argument('username',help='username of the user whose password you wish to reset')
    parser.add_argument('PIN', type=validate_pin, help='Four-digit PIN provided by the user')

    args = parser.parse_args()

    setpass = Setpass(auth_url, admin_user, admin_pwd, setpass_url)
    keystone = client.Client(session=setpass.session)
  
    user = [usr for usr in keystone.users.list() if usr.name == args.username]
    if not user:
        print "User {} not found".format(args.username)
        sys.exit(1)
    else:
        user = user[0]

    newpass = random_password(16)
    
    keystone.users.update(user, password=newpass)
    token = setpass.get_token(user.id, newpass, args.PIN)
   
    url = setpass.get_url(token)

    email_config = dict(config.items('password_email'))
    email = TemplateMessage(email=args.username, fullname=args.username, setpass_token_url=url, **email_config)
    try:
        email.send()
    except:
        email.dump_to_file(config)
        raise

   
