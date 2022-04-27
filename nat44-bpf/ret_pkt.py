#!/bin/python3

from scapy.all import *

dst_addr = "12.0.0.1"

pkt = IP(dst=dst_addr) / "PONGPONGPONG"

print(pkt.display())

send(pkt)
