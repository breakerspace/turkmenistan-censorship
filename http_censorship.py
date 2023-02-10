"""
Script to trigger HTTP censorship in Turkmenistan via an incomplete TCP packet
sequence given an IP address, censored domain, source port, and destination port
"""
import time
import argparse

from scapy.all import TCP, Raw, IP, send

def send_packets(input_ip, host_name, source_port, dest_port):
    """
    Sends an incomplete TCP handshake with a censored domain to trigger
    the censor to send a censoring response
    """
    #Creating a PSH+ACK packet with the censored domain in the payload
    pshack = IP(dst=input_ip)/TCP(dport=dest_port, sport=source_port,seq=101, flags="PA")/Raw("GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host_name))

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
