import binascii
import time
import logging
import argparse
import requests
import json
from scapy.all import *

logger = logging.getLogger('node-analyzer.py')

#Global variables
API_BASE_PATH = "/save-my-life"
FRAMES_ACTION = "/frames"

def analyzeSaveMyLife(packet):
    if (args != None):

        #packet.show()
        if packet.haslayer(Dot11ProbeReq):
            if (args.macToFilter == "" or packet.addr2[:32] == args.macToFilter):
                logger.info("packet found")
                print("Packet Found")
                # packet.show()

                print("<Probe_found>")
                print("\ttime = " + str(packet.time))  # time
                print("\tmac = " + packet.addr2[:32])  # mac
                print("\tSC = " + str(packet[Dot11].SC))  # SC - Sequence Control
                print("\tsignalStrength = " + str(packet.dBm_AntSignal))  # Signal Strength
                print("\tFullPacket")
                print("</Probe_found>")
                #packet.show()

                # preparing data to send to DB
                payload = {
                    "time": str(packet.time),
                    "mac": packet.addr2[:32],
                    "SC": str(packet[Dot11].SC),
                    "antenna": args.antenna,
                    "nodeLocation": args.nodeLocation,
                    "signalStrength": str(packet.dBm_AntSignal)
                }

                # Sending to seb Service
                print("Posting data to "+ args.server + API_BASE_PATH + FRAMES_ACTION + ">>" + json.dumps(payload))
                rserverResponse = requests.post(args.server + API_BASE_PATH + FRAMES_ACTION, json=payload)

                logger.info("Sent to server with status code: " + str(rserverResponse.status_code))
                logger.info("Response from server: " + rserverResponse.text)
    else:
        logger.error("args is null inside analyzeSaveMyLife method")

def setup():
    args = None
    # Check if SUDO
    # http://serverfault.com/questions/16767/check-admin-rights-inside-python-script
    if os.getuid() != 0:
        print("you must run sudo!")
        return None

    print("!! Homine-Unks presents: save-my-life  protocol example")

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--iface",
        default="wlan1",
        help="Wifi interface (wlan1 as default)")
    parser.add_argument(
        "-a",
        "--antenna",
        required=True,
        help="Define a name for the anthenna this node belongs to")
    parser.add_argument(
        "-n",
        "--nodeLocation",
        required=True,
        choices=['0', '120', '240'],
        help="Define the location in degrees where this node is located in the antenna")
    parser.add_argument(
        "-mf",
        "--macToFilter",
        help="Defile a mac addres, all Probe frames logged will belong only to this mac")
    parser.add_argument(
        "-s",
        "--server",
        default="https://71326931.us-south.apiconnect.appdomain.cloud",
        help="Define the server to perform Rest requests to save the Prove frames")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Set this to show detailed debug logged")
    args = parser.parse_args()

    # Check arguments for logging
    fh = logging.FileHandler('node-analyzer.log')
    ch = logging.StreamHandler()

    fh.setLevel(logging.INFO)
    ch.setLevel(logging.INFO)
    logger.setLevel(logging.INFO)
    if args.debug:
        fh.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(funcName)s:%(lineno)d - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)

    return args


# executing program
args = setup()

if(args != None):
    # sniffing in real time the content of the file
    print("Starting Sniffing with interface " + args.iface)
    sniff(iface=args.iface, prn=analyzeSaveMyLife)
else:
    print("Node could not initiate, use --help for more information")