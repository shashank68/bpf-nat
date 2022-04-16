#!/bin/python3

from scapy.all import *

# 11.0.1.2
dst_addr = "11.0.0.2"

pkt = IP(dst=dst_addr) / "PINGPINGPINGPINGPING"

print(pkt.display())

send(pkt)
