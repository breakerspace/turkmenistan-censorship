#!/bin/bash

iptables -I OUTPUT -p tcp --tcp-flags RST,ACK RST,ACK -d 95.85.96.0/19 -j DROP
iptables -I OUTPUT -p tcp --tcp-flags RST RST -d 95.85.96.0/19 -j DROP