------------------------------------------------------
sgTpushed2SWE server/agent proxy between ISE & SWE
------------------------------------------------------

The sgTpushed2SWE script updates dynamically host groups in Stealthwatch Enterprise
based on Trustsec SGTs tags.

It registers itself as a pxgrid client, and updates SMC with @IPs in dedicated groups.

The Trustsec SGT is used as the host group name, the parent group can be defined.

The configuration file is sgTpushed2SWE.conf.py; it has to be updated with your environement details

The script can be started directly from the cli, or from the sgTpushed2SWE.sh shell script to
get it working in background. Output provides some logging

Rate limiting can be enforced to limit load on SMC.

* Requires :
   - python >3.6
   - libraries : requests, asyncio, websockets
                stomp, ws_stomp (provided with the other files)
        stomp, ws_stomp are available here :
        https://github.com/cisco-pxgrid/pxgrid-rest-ws/tree/master/python
   - pxgrid websocket client requires to authenticate to the pxgrid server (ISE)
     with certificates; a pxgrid cert can be generated from ISE :
     Administration->Pxgrid Services->Certificates ; "I want to" (generate a single certificate without CSR)
     Export the ISE cert from Administration->Certificates->System certificates (cert used by pxgrid)

  - file included in the package :
    * README.txt : this file
    * stomp.py, ws_stomp.py : websocket libraries to connect to pxgrid server (ISE)
    * sgTpushed2SWE.py : the main program
    * sgTpushed2SWE_pxgrid.py : library used to manage the pxgrid websocket connection
    * sgTpushed2SWE_swe.py : library used to interact with SMC with API calls
    * sgTpushed2SWE_args.py : library used to managed options/environment variables
    * sgTpushed2SWE_conf.py : contains all options/environment variables
    * sgTpushed2SWE.sh : optional shell script to run the python script in background
    
  - to start the program from the CLI : python sgTpushed2SWE.py
  
  Overall process : <img width="1674" alt="Screenshot 2020-03-26 at 18 03 40" src="https://user-images.githubusercontent.com/22447118/77675334-1ca70080-6f8d-11ea-817c-d06bb813d496.png">
  
  Benefit : groups based on dynamic IPs learnt from pxgrid are available in reports, and can be part of the existing detection policies.
  
  <img width="1637" alt="Screenshot 2020-03-26 at 16 29 45" src="https://user-images.githubusercontent.com/22447118/77675878-d43c1280-6f8d-11ea-92a7-733ae570a39b.png">
<img width="1627" alt="Screenshot 2020-03-26 at 16 33 14" src="https://user-images.githubusercontent.com/22447118/77675882-d7370300-6f8d-11ea-9d28-12cdb1cec6b2.png">
