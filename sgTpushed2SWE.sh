#!/bin/bash

# __author__      = "Jean-Francois Pujol, Cisco Switzerland"
# __copyright__   = "MIT License. Copyright (c) 2020 Cisco and/or its affiliates."
# __version__     = 1.0

# chmod a+x ./sgTpushed2SWE.sh
# for running as a "daemon", can be started like : nohup ./sgTpushed2SWE.sh &

# cd /home/cisco/PxGrid
exec 1>sgTpushed2SWE.log 2>&1

source ./bin/activate

while [ 1 ]
do 
	python sgTpushed2SWE.py;
	sleep 5;
	echo "sgTpushed2SWE.py exited. $(date)"
done
