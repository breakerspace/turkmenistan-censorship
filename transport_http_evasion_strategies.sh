#!/bin/bash

# Script to run Geneva's transport layer strategies on HTTP requests 
# to a censored domain 

# Obtain command line arguments for server's IP address, censored domain, 
# and server/destination port. We do not need to obtain a source port as Geneva
# will randomize the source port for us
ip_address=$1
censored_domain=$2
server_port=$3

# Create an array of all the strategies to be tested
declare -a strategies=("[TCP:flags:PA]-fragment{tcp:8:True}-| \/" "[TCP:flags:S]-duplicate(,duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),))-| \/" "[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:R},)-| \/")

# Clone the Geneva repository and cd into it
git clone https://github.com/Kkevsterrr/geneva.git
cd geneva

# Iterate through all of the strategies and run each one
for i in "${strategies[@]}"
do
    echo "Running Strategy:" $i
    sudo python3 evolve.py --test-type http --protos http --log info --host-header $censored_domain -external-server --server $ip_address --port $server_port --bad-word $censored_domain --disable-port-negotiation --eval-only $i
    sleep 1
done