#!/bin/bash

ip_address=$1
censored_domain=$2
server_port=$3

declare -a strategies=("[TCP:flags:PA]-fragment{tcp:8:True}-| \/" "[TCP:flags:S]-duplicate(,duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),))-| \/" "[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:R},)-| \/")

git clone https://github.com/Kkevsterrr/geneva.git
cd geneva
for i in "${strategies[@]}"
do
    echo "Running Strategy:" $i
    sudo python3 evolve.py --test-type http --protos http --log info --host-header $censored_domain -external-server --server $ip_address --port $server_port --bad-word $censored_domain --disable-port-negotiation --eval-only $i
done