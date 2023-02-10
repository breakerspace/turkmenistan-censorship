"""
Script that evades DNS censorship in Turkmenistan by elevating counts above a threshold value
of 25. This script elevates the ancount value to 32 to evade DNS censorship.
"""
import sys
import argparse
from scapy.all import *

def send_dns_packet(ip, host_name):
    """
    Sends DNS query of censored domain with the ancount field set to 32
    """
    dns_req = IP(dst=ip)/UDP(dport=53)/DNS(rd=1, ancount=32, qd=DNSQR(qname=host_name))
    send(dns_req)     

def get_args():
    """
    Gets arguments from user.
    """
    parser = argparse.ArgumentParser(description="Turkmenistan HTTP Censorship Trigger via Incomplete TCP Handshake")
    parser.add_argument("--ip", type=str, help="IP address in Turkmenistan")
    parser.add_argument("--censored-domain", type=str, help="censored domain to send in HTTP request")
    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    send_dns_packet(args.ip, args.censored_domain)
