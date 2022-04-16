#!/bin/python3

from scapy.all import *

dst_addr = "12.0.0.1"

#dst_addr = "64:ff9b:0000:0000:0000:0000:0b00:0102"

pkt = IP(dst=dst_addr) / "PONGPONGPONG"

print(pkt.display())

send(pkt)
