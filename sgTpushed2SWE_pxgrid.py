#!/usr/bin/env python

"""
This script register a pxgrid node agent in ISE then,
set up a websocket connection waiting for messages from the pxgrid server.
 
"""
 
__copyright__   = "MIT License. Copyright (c) 2020 Cisco and/or its affiliates."
__version__     = 1.0
 
"""
Copyright (c) 2019, Cisco Systems, Inc. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import base64
import json
import urllib.request


class PxgridControl:
    def __init__(self, config):
        self.config = config

    def send_rest_request(self, url_suffix, payload):
        url = 'https://' + \
            self.config.ise_host()[0] + \
            ':8910/pxgrid/control/' + url_suffix
        print("pxgrid url=" + url)
        json_string = json.dumps(payload)
        print('  request=' + json_string)
        handler = urllib.request.HTTPSHandler(
            context=self.config.get_ssl_context())
        opener = urllib.request.build_opener(handler)
        rest_request = urllib.request.Request(
            url=url, data=str.encode(json_string))
        rest_request.add_header('Content-Type', 'application/json')
        rest_request.add_header('Accept', 'application/json')
        b64 = base64.b64encode((self.config.ise_nodename() +
        ':' + self.config.ise_password()).encode()).decode()
        rest_request.add_header('Authorization', 'Basic ' + b64)
        rest_response = opener.open(rest_request)
        response = rest_response.read().decode()
        print('  response=' + response)
        return json.loads(response)

    def account_activate(self):
        payload = {}
        if self.config.ise_node_description() is not None:
            payload['description'] = self.config.ise_node_description()
        return self.send_rest_request('AccountActivate', payload)

    def service_lookup(self, service_name):
        payload = {'name': service_name}
        return self.send_rest_request('ServiceLookup', payload)

    def service_register(self, service_name, properties):
        payload = {'name': service_name, 'properties': properties}
        return self.send_rest_request('ServiceRegister', payload)

    def get_access_secret(self, peer_node_name):
        payload = {'peerNodeName': peer_node_name}
        return self.send_rest_request('AccessSecret', payload)
