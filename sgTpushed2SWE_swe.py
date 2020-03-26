#!/usr/bin/env python

"""
This script will get and push data from/into Stealthwatch using the REST API.

For more information on this API, please visit:
https://developer.cisco.com/docs/stealthwatch/

 -

Script Dependencies:
    requests
Depencency Installation:
    $ pip install requests

System Requirements:
    Stealthwatch Version: 6.10.0 or higher

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

import requests
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass
import json
import time

"""
    ---------------------------------------------------------------------------------
    SmcControl Class used to interact with SMC trough API calls
    
    SMC API calls documentation refers to groups as "tags" ;
    group & tag are basically the same concept in SWE.
    
    For simplicity, the SMC group/tag is created
    with the same name as the incoming SGT bound to an @IP

    ---------------------------------------------------------------------------------
"""

class SmcControl:
    def __init__(self, config):
    
        self.config = config
    
        # Initialize the Requests session
        self.api_session = requests.Session()
        self.smc_login = {
            "username": self.config.smc_user(),
            "password": self.config.smc_password()
        }
        self.tag_list = []
        self.tenantId = 0
        self.apiRate = Speedo()
        self.lastAuth = int(time.time()) - 2 * self.config.smc_reauth()
        self.sgtRootTags = {}
        self.sgtRootName = ''
        self.auth_url = "https://" + self.config.smc_host() + "/token/v2/authenticate"
        self.tenant_url = 'https://' + self.config.smc_host() + '/sw-reporting/v1/tenants/'
        self.close_url = 'https://' + self.config.smc_host() + '/token'
        self.tag_url = 'https://' + self.config.smc_host() + '/smc-configuration/rest/v1/tenants/'
    
    """
        Authentication process to FMC
    """
    def authenticate(self):
    
        # authenticate only initially or after SMC_REAUTH
        now = int(time.time())
        if now - self.lastAuth < self.config.smc_reauth():
            # no need to re-authenticate
            return(True)
        
        self.apiRate.monitor()
        # after SMC_REAUTH, need to perform the POST request to login
        response = self.api_session.request("POST", self.auth_url, verify=False, data=self.smc_login)
        if(response.status_code == 200):
            self.lastAuth = now
            return(True)
        else:
            print("An error has ocurred, while logging in, with the following code {}".format(response.status_code))
            return(False)

    """
        Look for the tenant ID which is required to retrieve / post other data
    """
    def get_tenantID(self):
    
        # check for authentication
        self.authenticate()
        
        self.apiRate.monitor()
        # Get the list of tenants (domains) from the SMC
        response = self.api_session.request("GET", self.tenant_url, verify=False)
        if (response.status_code == 200):
            # Store the tenant (domain) ID
            tenant_list = json.loads(response.content)["data"]
            self.tenantId = tenant_list[0]["id"]
            print("Found SWE tenant ID = {}".format(self.tenantId))
        else:
            print("An error has ocurred, while fetching tenants (domains), with the following code {}".format(response.status_code))
    
    """
        List and store the existing host groups in the tenant.
        Host groups in the API calls library are named "tags"
        The result is a dictionnary with group/tag names and IDs
    """
    def tagList(self):
    
        # check for authentication
        self.authenticate()
        
        self.apiRate.monitor()
        url = self.tag_url + str(self.tenantId) + '/tags/'
        response = self.api_session.request("GET", url, verify=False)
        if (response.status_code == 200):
            # Return the list
            tag_list = json.loads(response.content)["data"]
            self.tag_list = tag_list
        # If unable to fetch list of tags (host groups)
        else:
            print("An error has ocurred, while fetching tags (host groups), with the following code {}".format(response.status_code))
            self.tag_list = []
            
        return(self.tag_list)
    
    """
        Retrieve all details for a particular tag (group) ID,
        including all @IPs already bound to it.
    """
    def tag_details(self, tagId):
        
        if tagId == '':
            return(self.config.smc_unknown_tag())
            
        # check for authentication
        self.authenticate()
        
        self.apiRate.monitor()
        url = self.tag_url + str(self.tenantId) + '/tags/' + str(tagId)
        response = self.api_session.request("GET", url, verify=False)
        if (response.status_code == 200):
            # Grab the tag details and check if the malicious IP is associated with this tag
            return(json.loads(response.content)["data"])
        else:
            print('## Unable to locate tag Id: {}, return code {}.'.format(tagId, response.status_code))
            if (response.status_code == 404): # not found, refresh the list
                self.tagList()  
            return(self.config.smc_unknown_tag())
    
    """
        Returns an ID from the tag/group dictionnary.
    """
    def tagIdFromName(self,tagName):
        
        for tag in self.tag_list:
            if tag['name'] == tagName:
                return(tag['id'])
        return('')

    """
        From the config file, verify the parent groups/tags are valid
    """
    def setSgtRootTags(self):
        
        sgtRootName = self.config.smc_sgt_default_parent()
        sgtRootTags = self.config.smc_sgt_parent_tags()
        
        # list of tag/group names found in SMC
        tagNames = set(item['name'] for item in self.tag_list)
        
        if sgtRootName not in tagNames:
            print(" !! Config error, >{}< group doesn't exist in SMC".format(sgtRootName))
            exit(-1)
        else:
            self.sgtRootName = sgtRootName
            
        for tag in sgtRootTags.values():
            if tag not in tagNames:
                print(" !! Config error, >{}< group doesn't exist in SMC".format(tag))
                exit(-1)
        self.sgtRootTags = sgtRootTags
    
    """
        Find a parent group/tag if configured, or return the default one.
    """
    def getSgtRootTag(self,sgtName):
        
        if sgtName in self.sgtRootTags.keys():
            return(self.sgtRootTags[sgtName])
        else:
            return(self.sgtRootName)
    
    """
        Creates a new group/tag in SMC
        Baselining for individual @IP is set to off
    """
    def createTag(self,tagName):
    
        # check for authentication
        self.authenticate()
        
        # Set the filter with the request data
        
        rootTagId = self.tagIdFromName(self.getSgtRootTag(tagName))
        
        tstamp = time.strftime("%y/%m/%d %H:%M:%S", time.gmtime())
        request_data = [
            {
                "name": tagName,
                "location": "INSIDE",
                "description": "ISE generated tag (SGT) group, created: {}".format(tstamp),
                "ranges": [],
                "hostBaselines": False,
                "suppressExcludedServices": True,
                "inverseSuppression": False,
                "hostTrap": False,
                "sendToCta": True,
                "parentId": rootTagId
            }
        ]

        # Add the new tag (host group) in the SMC
        self.apiRate.monitor()
        url = self.tag_url + str(self.tenantId) + '/tags'
        request_headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
        response = self.api_session.request("POST", url, verify=False, data=json.dumps(request_data), headers=request_headers)
        # If successfully able to add the tag (host group)
        if (response.status_code != 200):
            print("## Cannot create tag for :", tagName)
            # try refreshing the list in case some change was done in SMC
            self.tagList()
            return('')
        
        tagDetails= json.loads(response.content)["data"][0]
        tagId = tagDetails['id']
        
        # update tag list
        self.tag_list.append({'id' : tagId, 'name' : tagName})
        
        return(tagId)
    
    """
        Add an @IP into the range list in the tag/group 
    """
    def addIp2Tag(self,tagId,tagDetails,IpAddr):
    
        # check for authentication
        self.authenticate()
        
        url = self.tag_url + str(self.tenantId) + '/tags/' + str(tagId)
        # Modify the details of thee given tag (host group) from the SMC
        tagDetails['ranges'].append(IpAddr)

        self.apiRate.monitor()
        # Update the details of the given tag in the SMC
        request_headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
        response = self.api_session.request("PUT", url, verify=False, data=json.dumps(tagDetails), headers=request_headers)
        # If successfully able to update the tag (host group)
        updatedTagDetails = json.loads(response.content)["data"]
        if (response.status_code != 200) or IpAddr not in updatedTagDetails["ranges"]:
            print("Impossible to add Ip addr into tagId {} (code {}):".format(str(tagId),response.status_code))
    
    """
        Remove an @IP from the range list in the tag/group
    """
    def delIpFromTag(self,tagId,tagDetails,IpAddr):
    
        # check for authentication
        self.authenticate()
        
        url = self.tag_url + str(self.tenantId) + '/tags/' + str(tagId)
        # Modify the details of thee given tag (host group) from the SMC
        
        if IpAddr in tagDetails['ranges']:
            tagDetails['ranges'].remove(IpAddr)
        
        self.apiRate.monitor()
        # Update the details of the given tag in the SMC
        request_headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
        response = self.api_session.request("PUT", url, verify=False, data=json.dumps(tagDetails), headers=request_headers)
        # If successfully able to update the tag (host group)
        updatedTagDetails = json.loads(response.content)["data"]
        if (response.status_code != 200) or IpAddr in updatedTagDetails["ranges"]:
            print("Impossible to remove Ip addr from tagId {} (code {}):".format(str(tagId),response.status_code))
    
    # return the actual API call rate for rate limiting rules
    def callRate(self):
        return self.apiRate.rate()
    
    # return the number of SMC API calls already done since the script has started
    def callIndex(self):
        return self.apiRate.index()
        
    # Disconnects properly from the SMC
    def close(self):
    
        response = self.api_session.delete(self.close_url, timeout=30, verify=False)
        self.req +=1
        print('Disconnected from SWE')

"""
    ---------------------------------------------------------------------------------
    
    IpCache Class : IP@ <-> group/tag entries cache
    
    Avoids to fire an API call to SMC if the @IP was seen recently
    Format : { ip : tag }
    
    ---------------------------------------------------------------------------------

"""
class IpCache:
    def __init__(self, config):
        # Initialize the cache
        self.config = config
        self.cache = {}
        self.lastcleanup = int(time.time())
    
    """
        Updates an entry in the cache, and returns the old value
        if the @IP was present before.
    """
    def update(self,ip, tagId):
        
        tick = int(time.time())
        tag = { 'id' : tagId, 'tick' : tick }
        oldTagId = self.exists(ip)
        
        if oldTagId == None:
            # add the entry in the cache
            self.cache.update({ ip : tag })
            return(None)
        else:
            # IP already exists in the cache
            if tagId == oldTagId:
                # tag hasn't changed
                return(None)
            else:
                # tag changed, updating and returning the old one
                self.cache.update({ ip : tag })
                return(oldTagId)
    
    """
        Checks if an @IP exists in the cache
    """
    def exists(self, ip):
        
        if ip in self.cache.keys():
            return(self.cache[ip]['id'])
        else:
            return(None)
    
    """
        Removes an @IP / tag entry from the cache
    """
    def delete(self, IpAddr):
    
        if self.exists(IpAddr) != None:
            del self.cache[IpAddr]
    
    """
        Retrieve the latest time an @IP has been updated
    """
    def last(self, ip):
        
        if ip in self.cache.keys():
            return(self.cache[ip]['tick'])
        else:
            return(0)

    """
        Update the tick value for an @IP
        If not updated, the cache review will remove the @IP
        from SMC (and cache) after being aging out
    """
    def confirm(self, ip):
    
        tagId = self.exists(ip)
        if tagId:
            tick = int(time.time())
            tag = { 'id' : tagId, 'tick' : tick }
            self.cache.update({ ip : tag })
            return(tick)
        else:
            return(0)
    
    """
        Updates a list of @IPs an entry in the cache
    """
    def sync(self, tagId, IpAddresses):
    
        for IpAddr in IpAddresses:
            self.update(IpAddr,tagId)
    
    """
        Removes stale entries in the cache
    """
    def review(self):
    
        now = int(time.time())
        staleIPs = []

        if now - self.lastcleanup > self.config.cache_cleanup_time():
            print('* {} : cache review.'.format(time.strftime("%m-%d %H:%M:%S", time.gmtime())))
            for IpAddr in self.cache.keys():
                age = now - self.last(IpAddr)
                if age > self.config.cache_stale_ip():
                    localtime = time.localtime(now)
                    print('  -- {} age = {} (sec).'.format(IpAddr,age))
                    staleIPs.append(IpAddr)
                    
            self.lastcleanup = now
        
        return(staleIPs)
            
"""
    ---------------------------------------------------------------------------------
    
    Speedo Class used to rate the number of events (calls, messages, etc) per second
    
    Calculation made on the latest 5 seconds (per default)
     - monitor() takes the event in account
     - rate() reports the average of events / s
     - index() provides the actual index
     
    ---------------------------------------------------------------------------------
"""
class Speedo:
    def __init__(self, lapse = 5):
        self.req = 0
        self.req_clock = []
        self.lapse = lapse # in seconds
        
    def monitor(self):
        self.req +=1
        self.req_clock.append(time.time())
    
    def rate(self):
        now = time.time()
        for item in self.req_clock:
            if now - item > self.lapse: # rate calculated on self.lapse period of time
                self.req_clock.remove(item)
        rate = len(self.req_clock) / self.lapse
        return(rate)
    
    def index(self):
        return self.req
