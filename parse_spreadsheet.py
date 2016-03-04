__author__ = 'rahuls@ccs.neu.edu'

"""
Installation:-
pip install gspread
pip install oauth2client==1.5.2
"""

import json
import gspread
from oauth2client.client import SignedJwtAssertionCredentials


def get_details(auth_file, worksheet_key):
    json_key = json.load(open(auth_file))
    scope = ['https://spreadsheets.google.com/feeds']

    credentials = SignedJwtAssertionCredentials(json_key['client_email'],
                                                json_key['private_key'].encode(),
                                                scope)

    gc = gspread.authorize(credentials)
    worksheet = gc.open_by_key(worksheet_key).sheet1

    contents = []
    for rows in worksheet.get_all_values():
        contents.append(rows)

    projects = {}
    for entry in contents[1:]:
        if entry[0] == '':
            continue
        project = entry[1]
        name = entry[2] + " " + entry[3]
        email = entry[4]
        email = email.replace(u'\xa0', ' ').strip()

        req = {"name": name, "email": email}
        if project in projects:
            projects[project].append(req)
        else:
            projects[project] = [req]
    return projects


if __name__ == "__main__":
    # auth_file represents Google's service account key credentials filename
    auth_file = '--filename--'
    worksheet_key = "--key-here--"
    get_details(auth_file, worksheet_key)
