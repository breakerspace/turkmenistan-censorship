#!/bin/bash

# Script to run Geneva's transport layer strategies on HTTPS requests 
# to a censored domain 

# Function that will kill the engine running in the background and
# reset iptables
cleanup() {
    screen -S geneva -X quit 2> /dev/null
    iptables -F
    iptables -I OUTPUT -p tcp --tcp-flags RST,ACK RST,ACK -j DROP
    iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
}

# Obtain command line arguments for server's IP address, censored domain, 
# server/destination port, and source port.
ip_address=$1
censored_domain=$2
sport=$3
dport=$4

# Create an array of all the strategies to be tested
declare -a strategies=("[TCP:flags:PA]-fragment{tcp:4:True}-| \/" "[TCP:flags:S]-duplicate(,duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),))-| \/" "[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:R},)-| \/")

# Clone the Geneva repository and cd into it
git clone https://github.com/Kkevsterrr/geneva.git
cd geneva

# Iterate through all of the strategies
for i in "${strategies[@]}"
do
    echo "Running Strategy:" $i
    # Run the Geneva engine in the background for the current strategy
    screen -dmS geneva bash -c "python3 engine.py --server-port $dport --strategy \"$i\""
    sleep 1
    # Execute a curl command to the censored domain via HTTPS
    sudo curl --local-port $sport --connect-to ::$ip_address:$dport https://$censored_domain/
    sleep 1
    # Increment the source port by 1 for the next strategy
    sport=$((sport + 1))
done