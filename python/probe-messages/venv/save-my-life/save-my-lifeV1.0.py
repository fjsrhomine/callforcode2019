from scapy.all import *


# class Dot11EltRates(Packet):
#     """ Our own definition for the supported rates field """
#     name = "802.11 Rates Information Element"
#     # Our Test STA supports the rates 6, 9, 12, 18, 24, 36, 48 and 54 Mbps
#     supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
#     fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
#     for index, rate in enumerate(supported_rates):
#         fields_desc.append(ByteField("supported_rate{0}".format(index + 1),
#                                      rate))
#
#
# packet = Dot11(
#     addr1="00:a0:57:98:76:54",
#     addr2="00:a0:57:12:34:56",
#     addr3="00:a0:57:98:76:54") / Dot11AssoReq(
#     cap=0x1100, listen_interval=0x00a) / Dot11Elt(
#     ID=0, info="MY_BSSID")
# packet /= Dot11EltRates()
# sendp(packet, iface="wlan0")
# packet.show()


# target="www.target.com/30"
# ip=IP(dst=target)
# sendp(ip,iface="wlan0")

SSID = 'Test SSID'
iface = "wlan0"
sender="b8:27:eb:be:a8:12"
payload="Cosa extremadamanete grande para poder detectarla"

dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=sender, addr3=sender)
probe =Dot11ProbeReq()
essid=Dot11Elt(ID='SSID', info=SSID, len=len(SSID))

frame =RadioTap()/dot11/probe/essid/payload

sendp(frame, iface=iface)