#!/usr/bin/env python

"""
This file contains all options for the sgTpushed2SWE.py script.
Username/Password can be defined also on the command line ;
Try sgTpushed2SWE.py --help

 -

 Enter below all authentication info for SWE / SWE APIs to work
 
 Additional info to locate the right place for inserting new groups
 based on SGT tags.

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

# 

# Stealthwatch

SMC_USER = "admin" # used to post info by API calls
SMC_PASSWORD = "my_password"
SMC_HOST = "my.smcserver.ch"

SMC_SGT_DEFAULT_PARENT = "TAGS" # SMC default root tag name
SMC_SGT_PARENT_TAGS = { 'Dot1Xdesktops' : 'Trusted Users', # 'SGT name' : 'SMC parent tag/group name'
                        'Dot1Xmobiles' : 'Trusted Users',
                        'VPNusers' : 'Trusted Users',
                        'IPphones' : 'VoIP Endpoints' ,
                        'GuestPostAuth' : 'Guest Wireless' ,
                        'GuestPreAuth' : 'Guest Wireless'
                        }
SMC_REAUTH = 1500 # max time before re-auth, in seconds
SMC_MAX_RATE = 20 # max number of smc API access (/sec)
SMC_UNKNOWN_TAG = { } # empty list by default.

# ISE
ISE_NODENAME = "p_agent"
ISE_NODE_DESCRIPTION = "python agent for Stealthwatch integration"
ISE_HOST = ["myise.server.ch"]
ISE_PASSWORD = "mypassword"
ISE_CLIENTCERT = "./certs/sgTsubscribe2SWE_172.16.90.9.cer"
ISE_CLIENTKEY = "./certs/sgTsubscribe2SWE_172.16.90.9.key"
ISE_CLIENTKEYPASSWORD = "keycert_password_if_any"
ISE_SERVERCERT = "./certs/iserollelabch.crt"

# IP / TAG CACHE
CACHE_CLEANUP_TIME = 1800 # in seconds
CACHE_STALE_IP = 36000 # entry suppression after (in seconds)
CACHE_REMOVE_STALE_IP = "yes" # yes or no






