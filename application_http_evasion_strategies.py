"""
Script to evade HTTP censorship in Turkmenistan using application layer strategies
discovered by Geneva.
"""
import time
import random
import argparse

from scapy.all import *

def send_packets(input_ip, host_name, source_port, dest_port, strategy):
    """
    Completes a three-way handshake with an HTTP server and sends a manipulated,
    but valid HTTP request of a censored domain in order to bypass censorship
    """
    seq_no = random.randint(0, 4294967295)
    
    # Craft a SYN packet
    syn = IP(dst=input_ip)/TCP(seq=seq_no, flags='S', sport=source_port, dport=dest_port)
    send(syn, verbose=False)

    async_sniffer = AsyncSniffer()
    async_sniffer.start()

    # Wait for the SYN, ACK packet to come in
    time.sleep(2)

    results = async_sniffer.stop()

    # Get sequence number from SYN, ACK packet
    for pkt in results:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].src == input_ip and pkt[TCP].flags == "SA":
            syn_ack_seq = pkt[TCP].seq

    # Craft an ACK packet
    ack = IP(dst=input_ip)/TCP(seq=seq_no + 1, ack=syn_ack_seq + 1, flags="A", sport=source_port, dport=dest_port)
    send(ack)
    
    # Create raw payload for the HTTP GET request based on the strategy that the user wants to deploy
    if strategy == 1: # [HTTP:host:*]-insert{%09%0A:start:value:1}-| \/
        raw_payload = "GET / HTTP/1.1\r\nHost: \t\n{}\r\n\r\n".format(host_name)
    elif strategy == 2: # [HTTP:version:*]-insert{%20%0A%09:end:value:1}-| \/
        raw_payload = "GET / HTTP/1.1 \n\t\r\nHost: {}\r\n\r\n".format(host_name)
    elif strategy == 3: # [HTTP:method:*]-insert{%0A:start:value:1}-| \/
        raw_payload = "\nGET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host_name)
    elif strategy == 4: # [HTTP:host:*]-insert{%20:end:value:3391}(duplicate(duplicate(,replace{a:name:1}),insert{%09:start:name:1}),)-| \/
        raw_payload = "GET / HTTP/1.1 \r\n\tHost:{}".format(host_name)
        for i in range(0, 3391):
            raw_payload += " "
        raw_payload += "\r\nHost:{}".format(host_name)
        for i in range(0, 3391):
            raw_payload += " "
        raw_payload += "\r\na:twitter.com"
        for i in range(0, 3391):
            raw_payload += " "
        raw_payload += "\r\n\r\n"

    # Send the PSH+ACK packet with evasion strategy in raw payload
    pshack = IP(dst=input_ip)/TCP(dport=dest_port, sport=source_port, seq=seq_no+1, ack=syn_ack_seq + 1, flags="PA")/Raw(raw_payload)
    send(pshack)

def get_args():
    """
    Gets arguments from user.
    """
    parser = argparse.ArgumentParser(description="Turkmenistan Application-Layer HTTP Evasion Strategies")
    parser.add_argument("--ip", type=str, help="IP address in Turkmenistan")
    parser.add_argument("--censored-domain", type=str, help="censored domain to send in HTTP request")
    parser.add_argument("--sport", type=int, help="source port to use")
    parser.add_argument("--dport", type=int, help="destination port to use")
    parser.add_argument("--strategy", type=int, help="application layer http strategy to invoke, refer to README")
    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    send_packets(args.ip, args.censored_domain, args.sport, args.dport, args.strategy)
