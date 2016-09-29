## Installation of dependent packages
    pip install gspread
    pip install oauth2client==1.5.2

## Getting the Signed Credentials from Google
1. Goto [Google Developers Console](https://console.developers.google.com/project) and create a new project or select the existing one.
2. In "Auth & API", enable it and create "Service account key". [Referral link](http://gspread.readthedocs.org/en/latest/oauth2.html)
3. Place the "service account key" file in addusers directory and update the name in settings.ini file.
4. Share the google-spreadsheet with the email-address found within the "service-account-key" file.
5. Get the spreadsheet id and put it in settings.ini file.

## Usecase
These scripts are to create user account and project on openstack. 
The script can be run from the node which has keystoneclient and novaclient installed.

## How to use template_settings.ini
Copy the template_settings.ini to settings.ini and then fill the fields required in that file.

`bash$ cp settings_template.ini settings.ini`

Here is a sample copy of setting.ini file:-

    [auth]
    admin_user = admin
    admin_pwd = somepassword
    admin_tenant = admin
    auth_url = https://mycontroller.org:5000/v2.0

    [nova]
    version = 2

    [templates]
    email_template = ./email-template.txt
    password_template = ./password-template.txt

    [output]
    email_path = ./user_emails/
    password_path = ./password_emails/

## Mail Server Config

The mail server needs to have TLS enabled. If using postfix, add the 
following lines to /etc/postfix/main.cf:

smtpd_tls_cert_file = /path/to/cert/file
smtpd_tls_key_file = /path/to/key/file
smtpd_tls_security_level = may

If no certificate exists, one can be generated:
     openssl req -new -x509 -nodes -out /etc/postfix/postfix.pem -keyout /etc/postfix/postfix.pem -days 3650



