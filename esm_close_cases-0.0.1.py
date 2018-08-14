# -*- coding: utf-8 -*-

import base64
import json
import logging
import os
import requests
import sys
import urllib.parse as urlparse
from configparser import ConfigParser, NoSectionError
requests.packages.urllib3.disable_warnings()

class ESM(object):
    def __init__(self, hostname, username, password):
        """
        """
        self._host = hostname
        self._user = username
        self._passwd = password

        self._base_url = 'https://{}/rs/esm/'.format(self._host)
        self._int_url = 'https://{}/ess'.format(self._host)

        self._v9_creds = '{}:{}'.format(self._user, self._passwd)
        self._v9_b64_creds = base64.b64encode(self._v9_creds.encode('utf-8'))

        self._v10_b64_user = base64.b64encode(self._user.encode('utf-8')).decode()
        self._v10_b64_passwd = base64.b64encode(self._passwd.encode('utf-8')).decode()
        self._v10_params = {"username": self._v10_b64_user,
                            "password": self._v10_b64_passwd,
                            "locale": "en_US",
                            "os": "Win32"}
        self._headers = {'Content-Type': 'application/json'}

    def login(self):
        """
        Log into the ESM
        """
        self._headers = {'Authorization': 'Basic ' +
                         self._v9_b64_creds.decode('utf-8'),
                         'Content-Type': 'application/json'}
        self._method = 'login'
        self._data = self._v10_params
        self._resp = self.post(self._method, data=self._data,
                               headers=self._headers, raw=True)
        
        if self._resp.status_code in [400, 401]:
            print('Invalid username or password for the ESM')
            sys.exit(1)
        elif 402 <= self._resp.status_code <= 600:
            print('ESM Login Error:', self._resp.text)
            sys.exit(1)
        
        self._headers = {'Content-Type': 'application/json'}
        self._headers['Cookie'] = self._resp.headers.get('Set-Cookie')
        self._headers['X-Xsrf-Token'] = self._resp.headers.get('Xsrf-Token')
        self._headers['SID'] = self._resp.headers.get('Location')
        self._sid = self._headers['SID']

    def logout(self):
        """
        """
        self._url = self._base_url + 'logout'
        self._resp = requests.delete(self._url, headers=self._headers, verify=False)
                
    def get_cases(self):
        self._method = 'caseGetCaseList'
        self._resp = self.post(self._method, headers=self._headers)
        return(self._resp)        
        
    def close_case(self, case_id):
        self._method = 'caseEditCase'
        self._qdata = {"caseDetail": 
                        {"id": {"value": case_id}, 
                         'assignedTo': '1',
                         "statusId": {"value": 2}}}
        self._resp = self.post(self._method, data=self._qdata, headers=self._headers)

    def post(self, method, data=None, callback=None, raw=None,
             headers=None, verify=False):
        """
        """
        self._method = method
        self._data = data
        self._callback = callback
        self._headers = headers
        self._raw = raw
        self._verify = verify

        if not self._method:
            raise ValueError("Method must not be None")

        self._url = self._base_url + self._method
        if self._method == self._method.upper():
            self._url = self._int_url
            self._data = self._format_params(self._method, **self._data)
        else:
            self._url = self._base_url + self._method
            if self._data:
                self._data = json.dumps(self._data)
                
        self._resp = self._post(self._url, data=self._data,
                                headers=self._headers, verify=self._verify)

        if self._raw:
            return self._resp
        
        if 200 <= self._resp.status_code <= 300:
            try:
                self._resp = self._resp.json()
                self._resp = self._resp.get('return')
            except json.decoder.JSONDecodeError:
                self._resp = self._resp.text
            if self._method == self._method.upper():
                self._resp = self._format_resp(self._resp)
            if self._callback:
                self._resp = self._callback(self._resp)
            return self._resp
        if 400 <= self._resp.status_code <= 600:
            print('ESM Error:', self._resp.text)
            sys.exit(1)
           
    @staticmethod
    def _post(url, data=None, headers=None, verify=False):
        try:
            return requests.post(url, data=data, headers=headers,
                                 verify=verify)
        except requests.exceptions.ConnectionError:
            print("Unable to connect to ESM: {}".format(url))
            sys.exit(1)

def main():

    config = ConfigParser()
    config.read('.mfe_saw.ini')
    try:
        ini = dict(config.items('esm'))
    except NoSectionError:
        print("Section [esm] not found in mfe_saw.ini")
        sys.exit()
    
    esm = ESM(ini['esmhost'], ini['esmuser'], ini['esmpass'])
    esm.login()
    cases = esm.get_cases()
    for case in cases:
        esm.close_case(case['id']['value'])
    esm.logout()
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Control-C Pressed, stopping...")
        sys.exit()
