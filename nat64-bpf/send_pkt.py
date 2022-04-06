#!/bin/python3

from scapy.all import *

# 11.0.1.2
dst_addr = "64:ff9b:0000:0000:0000:0000:0b00:0102"

pkt = IPv6(dst=dst_addr) / "AAAAAAAAAAAAAAAAAAAAAAAAAAA"

print(pkt.display())

send(pkt)
