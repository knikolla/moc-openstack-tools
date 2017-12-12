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
"""Check whether there are new approved users on the spreadsheet

This script is designed to be run at intervals via cron to check
for updates to the spreadsheet and notify the helpdesk.

Each run of the script will:
    - Check for rows from the spreadsheet which have been approved, but the
      helpdesk hasn't been notified
    - Generate an email to the helpdesk in the correct format
    - Update the spreadsheet to indicate the helpdesk was notified
    - (Optional) log the processed requests to the specified log file
    - Check for quota requests that are almost expired or expired
    - If expired, generate email to the helpdesk
    - If almost expired, generate reminder email to the user
"""
import argparse
import ConfigParser
import string
from datetime import datetime, timedelta
from spreadsheet import Spreadsheet
from message import TemplateMessage
from config import set_config_file
from moc_utils import get_absolute_path
from dateutil import parser as dateparser


def parse_user_row(cells):
    """Parse the new approved User/Project request row"""
    email = cells[4].replace(u'\xa0', ' ').strip()
    user_info = {'user_name': email,
                 'user_email': email,
                 'first_name': cells[5],
                 'last_name': cells[6]}
    
    comment = 'User requested the following access:'.format(**user_info)
    
    REQUEST = "\n - {req}: `{detail}`"

    if cells[7] == 'No':
        req_type = 'new OpenStack user account'
        comment += REQUEST.format(req=req_type, detail=email)
    
    if cells[15] != '':
        req_type = 'new Openstack project'
        comment += REQUEST.format(req=req_type, detail=cells[15])
        user_info['project'] = cells[15]

        try:
            user_list = cells[17]
            req_type = "add existing users to new project"
            comment += REQUEST.format(req=req_type, detail=user_list)
        except IndexError:
            # it's OK for cells[17] not to exist at all
            pass
        
        # project description at the end because it might be long
        comment += "\n\nNew Project Description:\n{}".format(cells[16])
    
    elif cells[18] != '':
        req_type = 'access to existing OpenStack project'
        comment += REQUEST.format(req=req_type, detail=cells[18])
        user_info['project'] = cells[18]
        
    user_info['comment'] = comment
    return user_info


def parse_quota_row(cells):
    """Parse the new approved Quota request row"""
    # NOTE: cells[16] is a required field in the Google Form, so it is safe
    # to assume cells[0:15] exists.
    # cells[0] is Approved
    # cells[1] is Helpdesk Notified
    # cells[2] is Reminder Sent
    # cells[3] is Timestamp
    email = cells[4].replace(u'\xa0', ' ').strip()
    user_info = {'user_name': email,
                 'user_email': email,
                 'first_name': cells[5],
                 'last_name': cells[6],
                 # cells[7] is Organization
                 'project': cells[8]}

    # cells[9] is Type of Increase (Temp/Permanent)
    # cells[10] is End Date (for temp requests)

    comment = 'New quota request for project: {}'.format(user_info['project'])
    comment += "\n\nRequest Details:\n"
    
    # FIXME: this code block is lifted straight from set-quotas.py,
    # farm it out to a function somewhere to streamline updates.  Possibly
    # also update to use a list and for i in range().
    quotas = {'enddate': cells[10],
              'instances': cells[11],
              'cores': cells[12],
              'ram': cells[13],
              'floatingip': cells[14],
              'volumes': cells[15],
              'snapshots': cells[16],
              'gigabytes': cells[17]}
    unchanged_quotas = [q for q in quotas if quotas[q] == '']
    for quota_name in unchanged_quotas:
            del quotas[quota_name]
   
    # OpenStack wants the RAM quota in MB, but the form requests it in
    # GB so the users aren't confused by multiplying by 1000 vs. 1024
    if 'ram' in quotas:
        quotas['ram'] = int(quotas['ram']) * 1024
 
    REQUEST = "\n - {req}: {detail}"
    for qt in quotas:
        comment += REQUEST.format(req=qt, detail=quotas[qt])
        
    user_info['comment'] = comment
    return user_info


def notify_helpdesk(**request_info):
    """Populate and send an email to the helpdesk to open a ticket"""
    request_info.update(dict(config.items('email_defaults')))
    request_info.update(dict(config.items('helpdesk')))
    subject = 'MOC {}'.format(request_info['csr_type'])
    if 'project' not in request_info:
        request_info['project'] = 'N/A'
    msg = TemplateMessage(subject=subject, **request_info)
    msg.send()


def build_request_details(request_list, template):
    """Build the list of request details to be sent in the reminder message"""
    template = get_absolute_path(template)
    all_details = ""
    with open(template, "r") as f:
        detail_base = f.read()
    f.close()
    for request in request_list:
        item_details = detail_base
        for key in request:
            placeholder = "<{}>".format(key.upper())
            item_details = string.replace(item_details, placeholder,
                                          request[key])
        all_details += "\n-----\n{}".format(item_details)
    
    return all_details


def send_reminder(reminders, request_type, worksheet_key):
    """Send a reminder email about an application waiting for approval
    for more than a given # of hours (specified in config)
    """
    reminder_cfg = dict(config.items('email_defaults'))
    reminder_cfg.update(dict(config.items('reminder')))
    request_details = build_request_details(
        request_list=reminders, template=reminder_cfg['detail_template'])
    spreadsheet_link = 'https://docs.google.com/spreadsheets/d/{}'.format(
        worksheet_key)
    
    reminder_cfg.update({'request_count': str(len(reminders)),
                         'request_type': request_type,
                         'request_spreadsheet': spreadsheet_link,
                         'request_details': request_details})

    msg = TemplateMessage(**reminder_cfg)
    msg.send()


def timestamp_spreadsheet(sheet, time, rows, column):
    """Mark the given rows as notified in the Google Sheet"""
    # FIXME: consider whether spreadsheet.py should do some of this work,
    # particularly since below the private method _group_index is used

    # FIXME: Specify worksheet name in config
    worksheet = 'Form Responses 1'

    range_list = sheet._group_index(rows)
    request_list = []

    for rng in range_list:
        row_values = []
        for x in range(rng[1] - rng[0]):
            row_values.append(
                {'values': {'userEnteredValue': {'stringValue': time}}})
        update_req = {'updateCells': {
                      'rows': row_values,
                      'fields': '*',
                      'range': {
                          'sheetId': sheet.get_worksheet_id(worksheet),
                          'startRowIndex': rng[0],
                          'endRowIndex': rng[1],
                          'startColumnIndex': column,
                          'endColumnIndex': column + 1,
                      }}}
        request_list.append(update_req)
    
    batch = sheet.spreadsheets().batchUpdate(spreadsheetId=sheet._id,
                                             body={'requests': request_list})
    batch.execute()


def log_request(logfile, timestamp, user):
    """Note processed request in the log"""
    line = "{}    Helpdesk notified: request from {}\n".format(timestamp, user)
    with open(logfile, 'a') as f:
        f.write(line)
    f.close()


def check_requests(request_type, auth_file, worksheet_key):
    """Check for new approved requests"""
    # Some definitions that should eventually be set in config
    TIMESTAMP_FORMAT = "%d %b %Y %H:%M:%S"
    # hours until first reminder sent
    reminder_start = timedelta(hours=int(config.get('reminder', 'start')))
    # interval to send subsequent reminders
    reminder_interval = timedelta(hours=int(config.get('reminder',
                                                       'interval')))
    sheet = Spreadsheet(keyfile=auth_file, sheet_id=worksheet_key)
    rows = sheet.get_all_rows('Form Responses 1')
    timestamp = datetime.now().strftime(TIMESTAMP_FORMAT)
    processed_rows = []
    reminder_list = []
    reminder_rows = []
    now = datetime.now()
   
    # set some type-specific things
    if request_type == 'Access':
        parse_function = parse_user_row
        csr_type = 'Access Request'

    elif request_type == 'Quota':
        parse_function = parse_quota_row
        csr_type = 'Change Quota'
    else:
        raise Exception('Unknown request type: `{}`'.format(request_type))
    
    for idx, row in enumerate(rows):

        if (idx == 0) or (row == []):
            # skip header row and blank rows
            continue

        elif (row[0].lower().strip() == 'approved') and (row[1] == ''):
            # process rows that are marked approved but not notified
            request_info = parse_function(row)
            notify_helpdesk(csr_type=csr_type,
                            priority='High',
                            queue='Monitoring',
                            **request_info)
 
            processed_rows.append(idx)
            if args.log:
                log_request(args.log, timestamp, request_info['user_email'])
        
        # if request is not approved and is more than `reminder_start`
        # hours old, send a reminder
        elif row[0] == '' and (now >= dateparser.parse(row[3]) +
                               reminder_start):
            # but only send if this is the first one, or if enough time
            # has passed since the last one
            if row[2]:
                last_sent = datetime.strptime(row[2], TIMESTAMP_FORMAT)
            else:
                last_sent = None

            if not last_sent or (now >= last_sent + reminder_interval):
                request_info = parse_function(row)
                reminder_list.append(request_info)
                reminder_rows.append(idx)
        else:
            # skip over unapproved rows <24 hours old, or already-notified rows
            continue

    # Skip sending empty requests to Google API because it is slow and returns
    # an error.  Try/catch would handle the error but not avoid the time cost.
    if processed_rows:
        timestamp_spreadsheet(sheet, timestamp, processed_rows, column=1)
     
    if reminder_list:
        send_reminder(request_type=request_type,
                      reminders=reminder_list,
                      worksheet_key=worksheet_key)
        timestamp_spreadsheet(sheet, timestamp, reminder_rows, column=2)


def send_user_reminder(reminder):
    """Send a reminder email to user about a quota request
    which is within warning time of the expiration date
    """
    timestamp = reminder[3].split(" ", 1)[0]
    user_email = reminder[4].replace(u'\xa0', ' ').strip()
    user_fullname = reminder[5]
    project_name = reminder[8]
    end_date = reminder[10]

    reminder_cfg = dict(config.items('email_defaults'))
    reminder_cfg.update(dict(config.items('expiration_reminder')))
    reminder_cfg.update({'request_date': timestamp,
                         'email': user_email,
                         'fullname': user_fullname,
                         'project_name': project_name,
                         'end_date': end_date})
    msg = TemplateMessage(**reminder_cfg)
    msg.send()


def send_expired_reminders(reminders, worksheet_key):
    """Send a reminder email to helpdesk about a quota
    request which is past the expiration date
    """
    reminder_cfg = dict(config.items('email_defaults'))
    reminder_cfg.update(dict(config.items('expired_reminder')))
    request_details = build_request_details(
        request_list=reminders,
        template=dict(config.items('reminder'))['detail_template'])
    spreadsheet_link = 'https://docs.google.com/spreadsheets/d/{}'.format(
        worksheet_key)
    
    reminder_cfg.update({'request_count': str(len(reminders)),
                         'request_spreadsheet': spreadsheet_link,
                         'request_details': request_details})

    msg = TemplateMessage(**reminder_cfg)
    msg.send()


def check_expiration(auth_file, worksheet_key):
    TIMESTAMP_FORMAT = "%d %b %Y %H:%M:%S"
    warn_time = timedelta(hours=int(config.get('expiration_reminder',
                                               'warn_time')))
    now = datetime.now()
    timestamp = now.strftime(TIMESTAMP_FORMAT)

    sheet = Spreadsheet(keyfile=auth_file, sheet_id=worksheet_key)
    rows = sheet.get_all_rows('Form Responses 1')
    remind_user_list = []
    expired_list = []

    parse_function = parse_quota_row
    csr_type = 'Change Quota'

    for idx, row in enumerate(rows):

        # skip header row, blank row, or no end date
        if (idx == 0) or (row == []) or (row[10] == ''):
            continue

        end_date = datetime.strptime(row[10], "%m/%d/%Y")

        # if less than warn_time until expiration
        # send a reminder email to the user
        # (should we keep track of if/when we have notified user?)
        elif ((warn_time + end_date) >= now):
            request_info = parse_function(row)
            remind_user_list.append(request_info)

        # if we are past expiry date
        # send a notification to helpdesk to terminate resources
        elif ((now - end_date).days > 0):
            request_info = parse_function(row)
            expired_list.append(request_info)

        # skip rows that are not expired or close to expiring
        else:
            continue

    # send emails to remind users that their resources are expiring soon
    for reminder in remind_user_list:
        send_user_reminder(reminder=reminder)

    # send email to helpdesk to delete expired resources
    if expired_list:
        send_expired_reminders(reminders=expired_list,
                               worksheet_key=worksheet_key)

    # do we want to timestamp the spreadsheet?


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="Notify helpdesk of new approved requests")
    parser.add_argument('-c', '--config',
                        metavar="<config_file>",
                        help='Specify configuration file.')
    parser.add_argument('-l', '--log',
                        metavar='<log_file>',
                        help='Turn on logging and log to the specified file.')
    args = parser.parse_args()
   
    CONFIG_FILE = set_config_file(args.config)
    config = ConfigParser.ConfigParser()
    config.read(CONFIG_FILE)
    # FIXME right now it fails if full path to file is not specified
    # for auth_file, quota_auth_file, or helpdesk_template
    auth_file = get_absolute_path(config.get('excelsheet', 'auth_file'))
    worksheet_key = config.get('excelsheet', 'worksheet_key')
    reminder_email = config.get('reminder', 'email')
    reminder_template = get_absolute_path(config.get('reminder', 'template'))
    quota_auth_file = get_absolute_path(config.get('quota_sheet', 'auth_file'))
    quota_worksheet_key = config.get('quota_sheet', 'worksheet_key')
 
    check_requests('Access', auth_file, worksheet_key)
    check_requests('Quota', quota_auth_file, quota_worksheet_key)
    check_expiration(quota_auth_file, quota_worksheet_key)
