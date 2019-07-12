
import binascii
import time
from scapy.all import *

def customAction(packet):
    if packet.haslayer(Dot11ProbeReq):
        # packet.show()
        print("<Probe_found>")
        print("\ttime = " + str(packet.time))  # time
        print("\tmac = " + packet.addr2[:32])  # mac
        print("\tSC = " + str(packet[Dot11].SC))  # SC - Sequence Control
        print("</Probe_found>")


print("!! Homine-Unnks presents: save-my-life  protocol example")

# Getting the file name to work on
filename = input('Enter the path/fileName to work on: ')

# sniffing in real time the content of the file
sniff(offline=filename, prn=analyzeSaveMyLife)