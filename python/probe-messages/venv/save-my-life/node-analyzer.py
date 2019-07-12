import os
print os.sys.path

from scapy.all import *

scapy_cap = rdpcap('/tmp/tshark-temp_00006_20190712031104')
for packet in scapy_cap:
    packet.haslayer(Dot11ProbeReq)
    print packet[IPv6].src
