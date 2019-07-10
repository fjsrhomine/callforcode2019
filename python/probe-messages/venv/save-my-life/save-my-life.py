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

sendp((IP(dst="127.0.0.1",src="111.111.111.111")/UDP(dport=5005)/"Hello"),iface="wlan0")