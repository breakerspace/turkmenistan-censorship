"""
Script to trigger HTTPS censorship in Turkmenistan via an incomplete TCP packet
sequence given an IP address, censored domain, source port, and destination port
"""

import time
import argparse
from scapy.all import *

# Script to trigger HTTPS censorship via incomplete TCP packet sequences given an 
# IP address, censored domain, source port, and destination port

def send_packets(input_ip, host_name, source_port, dest_port):
    """
    Sends an incomplete TCP handshake with a Client Hello to trigger
    the censor to send a censoring response. The censored domain is within
    SNI field of the Client Hello.
    """
    #Creating the Client Hello payload with the censored domain in the SNI field
    tls_header = b'\x16\x03\x01'
    tls_length = (292 + len(host_name) + 5).to_bytes(2, "big")
    client_hello = b'\x01'
    client_hello_length = (288 + len(host_name) + 5).to_bytes(3, "big")
    everything_before_sni = bytearray.fromhex('03030a2e88d50cd009c068bc6570014358b0af11007ff5166126196bd13dfba831e520f0efa6c03671e01121660edb3b921c19a7978508e145de09a310279ecdc3537c003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000a9')
    extension_type = b'\x00\x00'
    server_name_extension_length = (len(host_name) + 5).to_bytes(2, "big")
    server_name_list_length = (len(host_name) + 3).to_bytes(2, "big")
    server_name_type = b'\x00'
    server_name_length = len(host_name).to_bytes(2, "big")
    server_name = bytes(host_name, "utf-8")
    everything_after_sni = bytearray.fromhex('000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d002005c2144a82a7fdad654118390cbb1df96600cb871ff6237294a81d4a347c3965')
    
    sni = b''.join([extension_type, server_name_extension_length, server_name_list_length, server_name_type, server_name_length, server_name])
    tls_payload = b''.join([tls_header, tls_length, client_hello, client_hello_length, everything_before_sni, sni, everything_after_sni])
    
    #Creating a PSH+ACK packet with the censored domain in the payload
    pshack = IP(dst=input_ip)/TCP(dport=dest_port, sport=source_port,seq=101, flags="PA")/Raw(tls_payload)
    
    #Sending first PSH+ACK packet with censored domain
    send(pshack)
    #Sleeping for 5 seconds, however we can sleep from anywhere between 5 to 29 seconds inclusive
    time.sleep(5)
    #Sending second PSH+ACK packet with censored domain
    send(pshack)
    
def get_args():
    """
    Gets arguments from user.
    """
    parser = argparse.ArgumentParser(description="Turkmenistan HTTP Censorship Trigger via Incomplete TCP Handshake")
    parser.add_argument("--ip", type=str, help="IP address in Turkmenistan")
    parser.add_argument("--censored-domain", type=str, help="censored domain to send in HTTP request")
    parser.add_argument("--sport", type=int, help="source port to use")
    parser.add_argument("--dport", type=int, help="destination port to use")
    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    send_packets(args.ip, args.censored_domain, args.sport, args.dport)