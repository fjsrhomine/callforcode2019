
import binascii
import time
from scapy.all import *

scapy_cap = rdpcap('/tmp/tshark-temp_00001_20190712040738')
for packet in scapy_cap:
    if packet.haslayer(Dot11ProbeReq):
        # packet.show()
        print("<Probe_found>")
        print("time = " + str(packet.time)) # time
        print("mac = " + packet.addr2[:32]) # mac
        print("SC = " + str(packet[Dot11].SC))  # SC - Sequence Control
        # if packet[Dot11][Dot11ProbeReq].haslayer(Dot11EltVendorSpecific):
            # packet[Dot11][Dot11ProbeReq][Dot11Elt][Dot11EltVendorSpecific].show()
            # print("SSID = " + binascii.b2a_base64(packet[Dot11][Dot11ProbeReq][Dot11Elt][Dot11EltVendorSpecific].info).decode('utf-8')[:32])
        print("</Probe_found>")