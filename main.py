import logging

from scapy.layers.inet import IP, ICMP, TCP
import scapy.all as scapy

l = logging.getLogger("scapy.runtime")
l.setLevel(49)

import os, sys, netfilterqueue, socket
from scapy.all import *


def process(payload):
    data = payload.get_payload()
    pkt = IP(data)
    print(pkt.mysummary())
    if static_filter(data):
        print("Accepting!")
        payload.accept()
    else:
        print("Dropping!")
        payload.drop()


def static_filter(data):
    pkt = IP(data)
    proto = pkt.proto
    print(data)
    print(pkt.fields)
    verdict = False

    if proto is 0x01:
        print("It's an ICMP packet")
        verdict = False
    # else:6
    #     print("It's an other packet")
    #     verdict = True

    elif proto is 0x06:

        print("It's an TCP packet")
        pkt = pkt.getlayer(1)
        # print(pl)
        print(pkt.fields)
        # print(pkt.dport)
        # port = pkt.fields['dport']
        # print('DPORT is ' + str(port))
        #
        # if int(port) == 8080:
        #     verdict = True
        # else:
        #     verdict = False

    else:
        print("It's an unknown proto! " + str(proto))
        verdict = False

    return verdict


def main():
    os.system("iptables -t nat -I PREROUTING -d 192.168.2.15 -j NFQUEUE --queue-num 1")

    q = netfilterqueue.NetfilterQueue()
    q.bind(1, process)

    try:
        print('starting')
        q.run()
    except:
        print('exiting')
        q.unbind()
        os.system("iptables -t nat -D PREROUTING -d 192.168.2.15 -j NFQUEUE --queue-num 1")
        sys.exit(1)


main()
