## Usecase
These scripts are to create user account and project on openstack. 
The script can be run from the node which has keystoneclient and novaclient installed.

## How to use template_settings.ini
Copy the template_settings.ini to settings.ini and then fill the fields required in that file.

`bash$ cp settings_template.ini settings.ini`

Here is a sample copy of setting.ini file:-

`[auth]`
`admin_user = admin`
`admin_pwd = somepassword`
`admin_tenant = admin`
`auth_url = https://mycontroller.org:5000/v2.0`
``
`[nova]`
`version = 2`
``
`[templates]`
`email_template = ./email-template.txt`
`password_template = ./password-template.txt`
``
`[output]`
`email_path = ./user_emails/`
`password_path = ./password_emails/`


