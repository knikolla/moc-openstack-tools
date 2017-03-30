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
"""Simple interface for interacting with Google Sheets API v4

To install the google-api-python-client:
    # pip install --upgrade google-api-python-client

Google Sheets API reference is:
    https://developers.google.com/sheets/reference/rest/
"""
import json
from httplib2 import Http
from operator import itemgetter
from itertools import groupby
from oauth2client.service_account import ServiceAccountCredentials

# googleapiclient
from googleapiclient.discovery import Resource
from googleapiclient.errors import HttpError
from googleapiclient.model import JsonModel
from googleapiclient.http import HttpRequest
from googleapiclient.schema import Schemas


class Spreadsheet(Resource):
    """ A wrapper around the Google API spreadsheet resource

    Constructs a spreadsheet API instance and creates user-friendly
    attributes and functions.
    """
    def __init__(self, keyfile, sheet_id):
        
        resource_args = self._build(keyfile)
        Resource.__init__(self, **resource_args)
        self._id = sheet_id

    def _build(self, key):
        """ Get all arguments needed to construct a Resource object.

        _build shortcuts the googleapiclient.discovery functions build()
        and build_from_document(), which construct the Resource class.
        
        See googleapiclient.discovery.Resource for more information.
        """
        # auth
        baseUrl = 'https://sheets.googleapis.com/'
        discUrl = (baseUrl + '$discovery/rest?version=v4')
        scope = ['https://spreadsheets.google.com/feeds']
        creds = ServiceAccountCredentials.from_json_keyfile_name(key, scope)
        http = creds.authorize(Http())
        
        # service JSON
        response, body = http.request(discUrl)
        if response.status >= 400:
            raise HttpError(response, body, uri=discUrl)
        service = json.loads(body)
        
        # model from service
        features = service.get('features', [])
        model = JsonModel('dataWrapper' in features)
        
        # schema from service
        schema = Schemas(service)
        
        return dict(http=http, baseUrl=baseUrl, model=model,
                    developerKey=None, requestBuilder=HttpRequest,
                    resourceDesc=service, rootDesc=service, schema=schema)
    
    def _get_info(self):
        """ Get JSON metadata about the spreadsheet """
        request = self.spreadsheets().get(spreadsheetId=self._id)
        return request.execute()
    
    def _get_rows(self, cell_range):
        """ Get values from the specified range

        Example cell_range to request A1:E5 on MyWorksheet:
            'MyWorksheet!A1:E5'
        """
        request = self.spreadsheets().values().get(spreadsheetId=self._id,
                                                   range=cell_range)
        rowdata = request.execute()
        return rowdata.get('values')

    def _batch_delete(self, worksheet_id, index_list, dimension):
        """ Send a batch request to delete rows or columns
            worksheet_id    id of the worksheet
            index_list      a list of row or column indexes to delete
            dimension       "ROWS" or "COLUMNS"

        Note that row/column indexes start at 0, so A1 is [0, 0]
        
        When changing this function, note that multiple deletes ** MUST **
        be ordered from highest to lowest row number in the request body.
        Otherwise, each delete changes the indices for rows that are still
        queued for deletion by the old index, and the wrong data is deleted.
        """
        
        delete_list = self._group_index(index_list)
        
        # Make sure deletes happen in a safe order!
        delete_list.reverse()
        
        # build the request body
        requests = []
        for x in delete_list:
            req_range = dict(sheetId=worksheet_id,
                             dimension=dimension,
                             startIndex=x[0],
                             endIndex=x[1])
            requests.append({"deleteDimension": {"range": req_range}})
        body = {"requests": requests}

        http_req = self.spreadsheets().batchUpdate(spreadsheetId=self._id,
                                                   body=body)
        return http_req.execute()

    def _group_index(self, index_list):

        """Process a list of indices into a list of ranges.
        
        The resulting list of ranges is for use in batch requests.

        Example:
            self._group_index([1,2,3,12,13,8,6]) returns:
            [ [1,4], [6,7], [8,9], [12,14] ]
        """
        range_list = []

        index_list.sort()

        # Find start/end index for each row or sequence of rows in the list
        for key, group in groupby(enumerate(index_list), lambda (i, x): i - x):
                grp = map(itemgetter(1), group)
             
                # Increment grp[-1] because the end index row is not deleted
                # so [start, end] = [5, 6] deletes row 5
                range_list.append([grp[0], grp[-1] + 1])
        
        return range_list
    
    def get_worksheet_id(self, name):
        """ Get the ID of the specified worksheet """
        info = self._get_info()
        match = (sheet['properties'] for sheet in info['sheets']
                 if sheet['properties']['title'] == name).next()
        if match is None:
            raise Exception('Worksheet not found: {}'.format(name))
        else:
            return match.get('sheetId')
     
    def get_all_rows(self, worksheet):
        """ Get all rows from the specified worksheet """
        cell_range = worksheet + "!A:Z"
        return self._get_rows(cell_range)

    def delete_rows(self, row_list, worksheet):
        """ Delete the given rows from the specified worksheet. """
        worksheet_id = self.get_worksheet_id(worksheet)
        return self._batch_delete(worksheet_id, row_list, "ROWS")
    
    def append_rows(self, rows, target, first_table_cell="A1"):
        """ Append rows to the specified target worksheet
        
        first_table_cell specifies where the top left corner of the table
        we are appending to is found.

        Specify INSERT_ROWS rather than the default overwrite behavior so
        data is not lost if the target sheet layout is weird and causes the
        append to happen in the wrong place.
        """
        cell_range = target + "!" + first_table_cell
        body = {"values": rows}
        req = self.spreadsheets().values().append(
            spreadsheetId=self._id, range=cell_range, valueInputOption='RAW',
            insertDataOption='INSERT_ROWS', body=body)
        return req.execute()
