os.sys.path.append('/usr/local/lib/python2.7/site-packages')

from scapy.all import *

scapy_cap = rdpcap('/tmp/tshark-temp_00006_20190712031104')
for packet in scapy_cap:
    packet.haslayer(Dot11ProbeReq)
    print packet[IPv6].src
