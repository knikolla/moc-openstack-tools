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
"""
import argparse
import ConfigParser
from datetime import datetime
from spreadsheet import Spreadsheet
from message import TemplateMessage
from config import set_config_file


def parse_user_row(cells):
    """Parse the new approved User/Project request row"""
    email = cells[3].replace(u'\xa0', ' ').strip()
    user_info = {'user_name': email,
                 'user_email': email,
                 'first_name': cells[4],
                 'last_name': cells[5]}
    
    comment = 'User requested the following access:'.format(**user_info)
    
    REQUEST = "\n - {req}: `{detail}`"

    if cells[6] == 'No':
        req_type = 'new OpenStack user account'
        comment += REQUEST.format(req=req_type, detail=email)
    
    if cells[14] != '':
        req_type = 'new Openstack project'
        comment += REQUEST.format(req=req_type, detail=cells[14])

        try:
            user_list = cells[16]
            req_type = "add existing users to new project"
            comment += REQUEST.format(req=req_type, detail=user_list)
        except IndexError:
            # it's OK for cells[16] not to exist at all
            pass
        
        # project description at the end because it might be long
        comment += "\n\nNew Project Description:\n{}".format(cells[15])
    
    elif cells[17] != '':
        req_type = 'access to existing OpenStack project'
        comment += REQUEST.format(req=req_type, detail=cells[17])
        
    user_info['comment'] = comment
    return user_info


def parse_quota_row(cells):
    """Parse the new approved Quota request row"""
    # NOTE: cells[16] is a required field in the Google Form, so it is safe
    # to assume cells[0:15] exists.
    email = cells[3].replace(u'\xa0', ' ').strip()
    user_info = {'user_name': email,
                 'user_email': email,
                 'first_name': cells[4],
                 'last_name': cells[5]}

    comment = 'User requested new quotas for project: {}'.format(cells[7])
    comment += "\n\nRequest Details:\n"
    
    # FIXME: this code block is lifted straight from set-quotas.py,
    # farm it out to a function somewhere to streamline updates.  Possibly
    # also update to use a list and for i in range().
    quotas = {'instances': cells[10],
              'cores': cells[11],
              'ram': cells[12],
              'floatingip': cells[13],
              'volumes': cells[14],
              'snapshots': cells[15],
              'gigabytes': cells[16]}
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


def notify_helpdesk(template, sender, receiver, **request_info):
    """Populate and send an email to the helpdesk to open a ticket"""
    subject = 'MOC {}'.format(request_info['csr_type'])
    msg = TemplateMessage(template=template, sender=sender, email=receiver,
                          subject=subject, **request_info)
    msg.send()


def timestamp_spreadsheet(sheet, time, processed_rows):
    """Mark the given rows as notified in the Google Sheet"""
    # FIXME: consider whether spreadsheet.py should do some of this work
    
    # FIXME: Specify worksheet name in config
    worksheet = 'Form Responses 1'
    range_list = sheet._group_index(processed_rows)
   
    request_list = []

    for rng in range_list:
        row_values = []
        for x in range(rng[1] - rng[0]):
            row_values.append({'userEnteredValue': {'stringValue': time}})
        update_req = {'updateCells': {
                      'rows': {'values': row_values},
                      'fields': '*',
                      'range': {
                          'sheetId': sheet.get_worksheet_id(worksheet),
                          'startRowIndex': rng[0],
                          'endRowIndex': rng[1],
                          'startColumnIndex': 1,
                          'endColumnIndex': 2,
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
    sheet = Spreadsheet(keyfile=auth_file, sheet_id=worksheet_key)
    rows = sheet.get_all_rows('Form Responses 1')
    timestamp = datetime.now().strftime("%d %b %Y %H:%M:%S")
    processed_rows = []
    
    # set som type-specific things
    if request_type == 'access':
        parse_function = parse_user_row
        csr_type = 'Access Request'

    elif request_type == 'quota':
        parse_function = parse_quota_row
        csr_type = 'Quota Request'
    else:
        raise Exception('Unknown request type: `{}`'.format(request_type))
    
    for idx, row in enumerate(rows):

        if (idx == 0) or (row == []):
            # skip header row and blank rows
            continue

        elif (row[0].lower().strip() == 'approved') and (row[1] == ''):
            # process rows that are marked approved but not notified
            request_info = parse_function(row)
            notify_helpdesk(template=helpdesk_template,
                            sender=helpdesk_email,
                            receiver=helpdesk_email,
                            csr_type=csr_type,
                            priority='High',
                            queue='Monitoring',
                            **request_info)
 
            processed_rows.append(idx)
            timestamp_spreadsheet(sheet, timestamp, processed_rows)
            if args.log:
                log_request(args.log, timestamp, request_info['user_email'])
        else:
            # skip over unapproved or already-notified rows
            continue


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
    auth_file = config.get('excelsheet', 'auth_file')
    worksheet_key = config.get('excelsheet', 'worksheet_key')
    helpdesk_email = config.get('helpdesk', 'email')
    helpdesk_template = config.get('helpdesk', 'access_template')
    quota_auth_file = config.get('quota_sheet', 'auth_file')
    quota_worksheet_key = config.get('quota_sheet', 'worksheet_key')
 
    check_requests('access', auth_file, worksheet_key)
    check_requests('quota', quota_auth_file, quota_worksheet_key)
