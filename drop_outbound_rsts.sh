#!/bin/bash

iptables -I OUTPUT -p tcp --tcp-flags RST,ACK RST,ACK -j DROP
iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP