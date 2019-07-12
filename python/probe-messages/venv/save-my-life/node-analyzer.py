
import binascii
import time
from scapy.all import *

def analyzeSaveMyLife(packet):
    if packet.haslayer(Dot11ProbeReq):
        if( filterThisMac =="" or packet.addr2[:32] == filterThisMac):
            # packet.show()
            print("<Probe_found>")
            print("\ttime = " + str(packet.time))  # time
            print("\tmac = " + packet.addr2[:32])  # mac
            print("\tSC = " + str(packet[Dot11].SC))  # SC - Sequence Control
            print("\tFullPacket")
            packet.show()
            print("</Probe_found>")


print("!! Homine-Unnks presents: save-my-life  protocol example")

# Getting the interface
iface = input('Enter the wifi interface (wlan1 for example): ')

# Getting the mac to filter
filterThisMac = input('Enter a MAC for a device to monitor (optional): ')

# sniffing in real time the content of the file
sniff(iface=iface, prn=analyzeSaveMyLife)