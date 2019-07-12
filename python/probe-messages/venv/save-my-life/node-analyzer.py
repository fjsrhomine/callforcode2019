from scapy.all import *

scapy_cap = rdpcap('/tmp/tshark-temp_00001_20190712035555')
for packet in scapy_cap:
    packet.haslayer(Dot11ProbeReq)
    print (packet[IPv6].src)
