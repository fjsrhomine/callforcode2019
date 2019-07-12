from scapy.all import *

class SaveMyLife(Packet):
    name = "SaveMyLife"
    fields_desc = [StrField("data", None)]


SSID = 'Test SSID'
iface = "wlan0"
sender="b8:27:eb:be:a8:12"
payload="Cosa extremadamanete grande para poder detectarla"

dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=sender, addr3=sender)
probe =Dot11ProbeReq()
essid=Dot11Elt(ID='SSID', info=SSID, len=len(SSID))
sml = SaveMyLife(data="Here I have some data to save my life")

frame =RadioTap()/dot11/probe/sml/essid/payload

sendp(frame, iface=iface)