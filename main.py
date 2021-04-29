import logging

from scapy.layers.inet import IP, ICMP, TCP
from scapy.all import wrpcap

l = logging.getLogger("scapy.runtime")
l.setLevel(49)

import os, sys, netfilterqueue, socket
from scapy.all import *


# def make_metrics(payload):



def process(payload):
    data = payload.get_payload()
    pkt = IP(data)
#    print(pkt.mysummary())
    if static_filter(data):
#        print("Accepting!")
        payload.accept()
    else:
#        print("Dropping!")
        payload.drop()


    wrpcap('tmp/tmppcap', pkt, append=True, sync=True)
    os.system("/opt/zeek/bin/zeek darpa2gurekddcup.bro -r tmp/tmppcap  > tmp/result 2>&1")

def static_filter(data):
    pkt = IP(data)
    proto = pkt.proto
#    print(data)
#    print(pkt.fields)
    verdict = False

    if proto is 0x01:
#        print("It's an ICMP packet")
        verdict = False
    # else:6
    #     print("It's an other packet")
    #     verdict = True

    elif proto is 0x06:

#        print("It's an TCP packet")
        pkt = pkt.getlayer(1)
        # print(pl)
#        print(pkt.fields)

        if pkt.fields['dport'] == 9090:
            verdict = True
#            print('Port is 9090!')
        else:
            verdict = False
#            print('Port is not 9090! :(')
        # print(pkt.dport)
        # port = pkt.fields['dport']
        # print('DPORT is ' + str(port))
        #
        # if int(port) == 8080:
        #     verdict = True
        # else:
        #     verdict = False

    else:
#        print("It's an unknown proto! " + str(proto))
        verdict = False

    return verdict


def main():
    os.system("(ls tmp/ && continue || mkdir tmp) && (umount $(pwd)/tmp || mount -t ramfs -o size=1G ramfs $(pwd)/tmp)")

    os.system("iptables -t raw -I PREROUTING -d 192.168.2.15 -j NFQUEUE --queue-num 0")

    os.system("rm -f tmppcap")
    q = netfilterqueue.NetfilterQueue()
    q.bind(0, process)

    try:
        print('starting')
        q.run()
    except:
        print('exiting')
        q.unbind()
        os.system("iptables -t raw -D PREROUTING -d 192.168.2.15 -j NFQUEUE --queue-num 0")
        os.system("umount $(pwd)/tmp")
        sys.exit(1)


main()
