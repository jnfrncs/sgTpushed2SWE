#!/usr/bin/env python

"""
This script will subscribe to pxgrid and publish all learned @IPs to
StealthWatch Enterprise into groups having the corresponding SGT name.

There is dynamic cache to avoid all pxgrid updates to be replicated to
SWE. Additional rate limiting is available to take some load off the
SWE API calls.

Static options / configurations variables should be defined in
sgTpushed2SWE_conf.py file.

Script Dependencies:
    python 3.6
    asyncio
    websockets
    stomp, ws_stomp
        stomp, ws_stomp are available here :
        https://github.com/cisco-pxgrid/pxgrid-rest-ws/tree/master/python
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


import asyncio
from asyncio.tasks import FIRST_COMPLETED
import json
import sys
import time
from websockets import ConnectionClosed
from ws_stomp import WebSocketStomp

from sgTpushed2SWE_pxgrid import PxgridControl
from sgTpushed2SWE_swe import SmcControl, IpCache, Speedo
from sgTpushed2SWE_args import Config

def ipTagCache_cleanup(config,staleIPs, smc, ipTags):

    if config.cache_remove_stale_ip():
        for IpAddr in staleIPs:
            tagId = ipTags.exists(IpAddr)
            tagDetails = smc.tag_details(tagId)
            tagName = tagDetails['name']
            print("*  Stale IP ({}), removing it from tag {} - rate/s : {:.1f}.".format(IpAddr, tagName, smc.callRate() ), flush=True)
            smc.delIpFromTag(tagId, tagDetails, IpAddr)
            ipTags.delete(IpAddr)

def key_enter_callback(event):
    sys.stdin.readline()
    event.set()   

async def future_read_message(ws, future):
    try:
        message = await ws.stomp_read_message()
        future.set_result(message)
    except ConnectionClosed:
        print('Websocket connection closed')

async def subscribe_loop(config, secret, ws_url, topic, smc):

    global ipTags
    
    ws = WebSocketStomp(ws_url, config.ise_nodename(), secret, config.get_ssl_context())
    await ws.connect()
    await ws.stomp_connect(pubsub_node_name)
    await ws.stomp_subscribe(topic)
    
    print("{TIME} ({Index of pxgrid msg}/{Index of SWE API calls made}) PxGrid -> sgt: {TAG} IPs: {IP} ")
    
    while True:
        future = asyncio.Future()
        future_read = future_read_message(ws, future)
        await asyncio.wait([future_read], return_when=FIRST_COMPLETED)
        
        message = json.loads(future.result())
        session = message['sessions'][0]
    
        pxRawRate.monitor()
        
        if 'ctsSecurityGroup' in session.keys() and 'ipAddresses' in session.keys() :
            
            now = int(time.time())
            pxIpRate.monitor()
            
            ipAddresses = session['ipAddresses']
            sgtName = session['ctsSecurityGroup']
            tstamp = time.strftime("%H:%M:%S", time.gmtime())
            listOfIPs = " ".join(ipAddresses)
            print("{} ({}/{}) PxGrid -> sgt: {} IPs: {} rate {:.1f}/s|{:.1f}/s".format(tstamp,pxIpRate.index(),smc.callIndex(),sgtName,listOfIPs,pxRawRate.rate(), pxIpRate.rate()), flush=True)
            
            # SMC call rate limit verification
            smcRate = smc.callRate()
            if smcRate > config.smc_max_rate():
                print(" *** SMC API max call rate reached ({:.1f}/s), cancelling pxgrid record ".format(smcRate))
                continue
                
            tagId = smc.tagIdFromName(sgtName) # tag/group name cache lookup
            
            if tagId == '':
                # group/tag doesn't exit yet; needs to be created
                print("({}/{}) New tag ({}), creation in SMC - (rate/s : {:.1f}).".format(pxIpRate.index(),smc.callIndex(),sgtName,smc.callRate()), flush=True)
                tagId = smc.createTag(sgtName) # smc API; one query.
                if tagId == '':
                    # impossible to create
                    print("### Error: Impossible to create new tag ({}).".format(sgtName), flush=True)
                    continue
                    
            for IpAddr in ipAddresses:
                if IpAddr == '':
                    continue
                # for each IP address in the pxgrid message :
                cachedIpTag = ipTags.exists(IpAddr) # cache IP lookup, could return None
                if tagId != cachedIpTag: # actual group/tag in cache is unknown or different from received
                    # update the Tag cache
                    ipTags.update(IpAddr,tagId)
                    # retrieve the config of the new Tag (group)
                    tagDetails = smc.tag_details(tagId) # smc API; one query
                    
                    if tagDetails == config.smc_unknown_tag() :
                        print("### Error: Impossible to get the tagId ({}) details.".format(tagId), flush=True)
                        ipTags.delete(IpAddr) # in case sync is lost with FMC
                        print(' ## {}/{} update message not processed.'.format(sgtName,IpAddr))
                        continue # no way to get the tag details;
                    
                    if 'ranges' in tagDetails:
                        #update the cache with @IPs found in SMC in the group/tag
                        ipTags.sync(tagId,tagDetails['ranges']) 
                    
                        if IpAddr in tagDetails['ranges']:
                            age = int((now - ipTags.last(IpAddr))/60) # in minutes
                            print("  Tag ({}), {} present in SMC (age {} min.) - rate/s : {:.1f}.".format(sgtName, IpAddr, age, smc.callRate() ), flush=True)
                        else:
                            print("  Tag ({}), {} not found in SMC, adding it - rate/s : {:.1f}.".format(sgtName, IpAddr,smc.callRate() ), flush=True)
                            smc.addIp2Tag(tagId,tagDetails,IpAddr) # smc API; one query
                    else:
                        print('## Warning: missing  details for {}.'.format(tagId))
                    
                    if cachedIpTag != None: # @IP was present in another group/tag;
                        # retrieve the config of the old Tag (group)
                        tagDetails = smc.tag_details(cachedIpTag) # smc API; one query
                        tagName = tagDetails['name']
                        ipTags.sync(tagId,tagDetails['ranges']) #by the way, update the cache with all @IPs found
                        if IpAddr in tagDetails['ranges']:
                            print("  Old tag ({}), {} present in SMC, removing it - rate/s : {:.1f}.".format(tagName, IpAddr, smc.callRate() ), flush=True)
                            smc.delIpFromTag(tagId,tagDetails,IpAddr)
                        else:
                            print("  Old tag ({}), {} not found in SMC, no change.".format(tagName, IpAddr ), flush=True)
        
                else: # known @IP, in the correct group/tag
                    age = int((now - ipTags.last(IpAddr))/60) # in minutes
                    print("  Tag ({}), @IP ({}) present in cache, no change (age {} min.).".format(sgtName, IpAddr, age ), flush=True)
                    ipTags.confirm(IpAddr) # reset the age in the cache.
                
                # cleaning up the ipTags cache
                staleIPs = ipTags.review()
                ipTagCache_cleanup(config, staleIPs, smc, ipTags)
                        

if __name__ == '__main__':

    assert (sys.version_info >= (3, 6)), "Requires Python 3.6 min."
    
    config = Config()
    pxgrid = PxgridControl(config)
    pxRawRate = Speedo()
    pxIpRate = Speedo()
    smc = SmcControl(config)
    ipTags = IpCache(config)

    while pxgrid.account_activate()['accountState'] != 'ENABLED':
        time.sleep(60)

    # lookup for session service
    service_lookup_response = pxgrid.service_lookup('com.cisco.ise.session')
    service = service_lookup_response['services'][0]
    pubsub_service_name = service['properties']['wsPubsubService']
    topic = service['properties']['sessionTopic']

    # lookup for pubsub service
    service_lookup_response = pxgrid.service_lookup(pubsub_service_name)
    pubsub_service = service_lookup_response['services'][0]
    pubsub_node_name = pubsub_service['nodeName']
    secret = pxgrid.get_access_secret(pubsub_node_name)['secret']
    ws_url = pubsub_service['properties']['wsUrl']
    
    # authenticate to Stealthwatch and set SMC environment
    smc.authenticate()
    smc.get_tenantID()
    smc.tagList()
    smc.setSgtRootTags()

    asyncio.get_event_loop().run_until_complete(subscribe_loop(config, secret, ws_url, topic, smc))
