## Dependencies

Packages:

    python-keystoneclient
    python-novaclient
    python-neutronclient
    python-cinderclient
    google-api-python-client

The script also requires a TLS-capable mail server to be running.  We have 
used this code with both Sendmail and Postfix.  See 
[below](#mail-server-config) for the Postfix config required to enable TLS.

## Getting the Signed Credentials from Google
1. Goto [Google Developers Console](https://console.developers.google.com/project) and create a new project or select the existing one.
2. In "Auth & API", enable it and create "Service account key". [Referral link](http://gspread.readthedocs.org/en/latest/oauth2.html)
3. Place the "service account key" file in addusers directory and update the name in settings.ini file.
4. Share the google-spreadsheet with the email-address found within the "service-account-key" file.
5. Get the spreadsheet id and put it in settings.ini file.

## Usecase
These scripts simplify the process of:

1. Creating users and projects in OpenStack, including defining project quotas.
2. Sending a welcome email to new users.
3. Using [Setpass](https://github.com/CCI-MOC/setpass) to email a link that allows new users to set their password securely.
4. Resetting a user's password if they forget it, also via Setpass.

New user data is assumed to be in a Google Sheet. The function parse_rows in addusers.py handles parsing the spreadsheet data, you may need to modify it to work with your particular spreadsheet format.

## How to use example_settings.ini
Copy the examplee_settings.ini to settings.ini and then fill the fields required in that file.

## Mail Server Config

The mail server needs to have TLS enabled. If using postfix, add the 
following lines to /etc/postfix/main.cf:

     smtpd_tls_cert_file = /path/to/cert/file
     smtpd_tls_key_file = /path/to/key/file
     smtpd_tls_security_level = may

If no certificate exists, one can be generated:
     
     openssl req -new -x509 -nodes -out /etc/postfix/postfix.pem -keyout /etc/postfix/postfix.pem -days 3650

