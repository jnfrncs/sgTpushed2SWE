#!/usr/bin/env python

"""
This script will manage CLI options for sgTpushed2SWE.py.

Static options / configurations variables should be defined in
sgTpushed2SWE_conf.py file
 -
 
 """
 
__author__      = "Jean-Francois Pujol, Cisco Switzerland"
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

import argparse
import ssl


"""
    Imports configuration variables from the sgTpushed2SWE_conf.py file.
    User / password values can also be supplied as arguments on the CLI
    
""" 
from sgTpushed2SWE_conf import *


class Config:
    def __init__(self):
        
        parser = argparse.ArgumentParser()
        parser.add_argument('--ise_user', help='ISE admin user')
        parser.add_argument('--ise_password', help='ISE admin password')
        parser.add_argument('--smc_user', help='SMC admin user')
        parser.add_argument('--smc_password', help='SMC admin password')
            
        self.config = parser.parse_args()
        
        if 'SMC_USER' not in globals() and 'smc_user' not in self.config:
            print("Error: Missing SMC_USER entry in configuration file or smc_user cli option.")
            exit(0)
        else:
            if 'smc_user' not in self.config or self.config.smc_user == None:
                self.config.smc_user = SMC_USER
        
        if 'SMC_PASSWORD' not in globals() and 'smc_password' not in self.config:
            print("Error: Missing SMC_PASSWORD entry in configuration file or smc_password cli option.")
            exit(0)
        else:
            if 'smc_password' not in self.config or self.config.smc_password == None:
                self.config.smc_password = SMC_PASSWORD
        
        if 'SMC_HOST' not in globals():
            print("Error: Missing SMC_HOST entry in configuration file.")
            print("  - string: SMC management IP or DNS name")
            exit(0)
        else:
            self.config.smc_host = SMC_HOST
            
        if 'SMC_REAUTH' not in globals():
            print("Error: Missing SMC_REAUTH entry in configuration file.")
            print("  - in seconds / integer; ex: 1500 ")
            print("  - should be lower than the max delay before re-authentication to SMC")
            exit(0)
        else:
            self.config.smc_reauth = SMC_REAUTH
            
        if 'SMC_MAX_RATE' not in globals():
            print("Error: Missing SMC_MAX_RATE entry in configuration file.")
            print("  - integer ; max number of smc API access (/sec); ex: 10 ")
            exit(0)
        else:
            self.config.smc_max_rate = SMC_MAX_RATE
            
        if 'SMC_UNKNOWN_TAG' not in globals():
            self.config.smc_unknown_tag = {}
        else:
            self.config.smc_unknown_tag = SMC_UNKNOWN_TAG
        
        if 'CACHE_CLEANUP_TIME' not in globals():
            print("Error: Missing CACHE_CLEANUP_TIME entry in configuration file.")
            print("  - in seconds / integer; ex: 1800")
            exit(0)
        else:
            self.config.cleanup_time = CACHE_CLEANUP_TIME
        
        if 'CACHE_STALE_IP' not in globals():
            print("Error: Missing CACHE_STALE_IP entry in configuration file.")
            print("  - in seconds / integer; ex: 36000")
            exit(0)
        else:
            self.config.cache_stale_ip = CACHE_STALE_IP
        
        if 'CACHE_REMOVE_STALE_IP' not in globals():
            print("Error: Missing CACHE_REMOVE_STALE_IP entry in configuration file.")
            print("  - string : yes/no; yes = remove @IPs after CACHE_STALE_IP without new refresh from pxgrid.")
            exit(0)
        else:
            self.config.cache_remove_stale_ip = CACHE_REMOVE_STALE_IP
        
        if 'SMC_SGT_DEFAULT_PARENT' not in globals():
            print("Error: Missing SMC_SGT_DEFAULT_PARENT entry in configuration file.")
            print("  - string: SMC group name used as parent group by default ")
            exit(0)
        else:
            self.config.smc_sgt_default_parent = SMC_SGT_DEFAULT_PARENT
        
        if 'SMC_SGT_PARENT_TAGS' not in globals():
            print("Error: Missing SMC_SGT_PARENT_TAGS entry in configuration file.")
            print("  - dictionnary: { SGT_NAME : SMC_PARENT_GROUP, etc...}")
            exit(0)
        else:
            self.config.smc_sgt_parent_tags = SMC_SGT_PARENT_TAGS
                
        if 'ISE_NODENAME' not in globals():
            print("Error: Missing ISE_NODENAME entry in configuration file.")
            print("  - string: name of the agent register into the pxgrid server")
            exit(0)
        else:
            self.config.ise_nodename = ISE_NODENAME
            
        if 'ISE_NODE_DESCRIPTION' not in globals():
            print("Error: Missing ISE_NODE_DESCRIPTION entry in configuration file.")
            print("  - string: description of the agent registering into the pxgrid server")
            exit(0)
        else:
            self.config.ise_node_description = ISE_NODE_DESCRIPTION
            
        if 'ISE_PASSWORD' not in globals():
            print("Error: Missing ISE_PASSWORD entry in configuration file.")
            print("  - string: admin password used to register the agent into the pxgrid server")
            exit(0)
        else:
            if 'ise_password' not in self.config or self.config.ise_password == None:
                self.config.ise_password = ISE_PASSWORD
            
        if 'ISE_HOST' not in globals():
            print("Error: Missing ISE_HOST entry in configuration file.")
            print("  - list: ISE pxgrid PSNs / IPs or DNS names; ex: [\"10.0.0.1\",\"10.0.0.2\"]")
            exit(0)
        else:
            self.config.ise_host = ISE_HOST
    
        if 'ISE_CLIENTCERT' not in globals():
            print("Error: Missing ISE_CLIENTCERT entry in configuration file.")
            print("  - string : path to the pxgrid agent cert file used to register to the ISE/pxgrid server (.crt format)")
            exit(0)
        else:
            self.config.ise_client_cert = ISE_CLIENTCERT
            
        if 'ISE_CLIENTKEY' not in globals():
            print("Error: Missing ISE_CLIENTKEY entry in configuration file.")
            print("  - string : path to the pxgrid agent cert key file (.key / crt format)")
            exit(0)
        else:
            self.config.ise_client_key = ISE_CLIENTKEY
            
        if 'ISE_CLIENTKEYPASSWORD' not in globals():
            print("Error: Missing ISE_CLIENTKEYPASSWORD entry in configuration file.")
            print("  - string : key to decrypt the pxgrid agent cert key file (or \"\" if not encrypted)")
            exit(0)
        else:
            self.config.ise_client_key_password = ISE_CLIENTKEYPASSWORD
    
        if 'ISE_SERVERCERT' not in globals():
            print("Error: Missing ISE_SERVERCERT entry in configuration file.")
            print("  - string : path to the pxgrid server (ise) cert file (.crt format)")
            exit(0)
        else:
            self.config.ise_server_cert = ISE_SERVERCERT
        
    def smc_user(self):
        return self.config.smc_user
    
    def smc_password(self):
        return self.config.smc_password
        
    def smc_host(self):
        return self.config.smc_host
        
    def smc_reauth(self):
        return self.config.smc_reauth

    def smc_max_rate(self):
        return self.config.smc_max_rate
    
    def smc_unknown_tag(self):
        return self.config.smc_unknown_tag
    
    def cache_cleanup_time(self):
        return self.config.cleanup_time
    
    def cache_stale_ip(self):
        return self.config.cache_stale_ip
    
    def cache_remove_stale_ip(self):
        return self.config.cache_remove_stale_ip
    
    def smc_sgt_default_parent(self):
        return self.config.smc_sgt_default_parent
    
    def smc_sgt_parent_tags(self):
        return self.config.smc_sgt_parent_tags
    
    def ise_nodename(self):
        return self.config.ise_nodename
    
    def ise_node_description(self):
        return self.config.ise_node_description
    
    def ise_password(self):
        return self.config.ise_password
    
    def ise_host(self):
        return self.config.ise_host
    
    def ise_client_cert(self):
        return self.ise_client_cert
    
    def ise_client_key(self):
        return self.config.ise_client_key
    
    def ise_client_key_password(self):
        return self.config.ise_client_key_password
    
    def ise_server_cert(self):
        return self.config.ise_server_cert
        
    def get_ssl_context(self):
        context = ssl.create_default_context()
        if self.config.ise_client_cert is not None:
            context.load_cert_chain(certfile=self.config.ise_client_cert,
                                    keyfile=self.config.ise_client_key,
                                    password=self.config.ise_client_key_password)
        context.load_verify_locations(cafile=self.config.ise_server_cert)
        return context
