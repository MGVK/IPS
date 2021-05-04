import logging

from scapy.layers.inet import IP, ICMP, TCP
import threading
from scapy.all import wrpcap

l = logging.getLogger("scapy.runtime")
l.setLevel(49)

import os, sys, netfilterqueue, socket
from scapy.all import *

DIRECTION_INPUT = 'input'
DIRECTION_OUTPUT = 'output'

common_count = 0
sessions_count = 0
debug_enabled = True
last_pkt = None

tcp_sessions = list()


class TCPSession(object):

    def __init__(self, pkt, number):
        if not hasattr(self, 'pkts'):
            self.pkts = list()
        self.pkts.append(pkt)
        self.session_number = number

    def add_if_match(self, pkt):
        # debug(type(pkt))
        if pkt is not None and (len(self.pkts) == 0
                                or self.pkts[-1].answers(pkt)
                                or pkt.answers(self.pkts[-1])):
            self.pkts.append(pkt)
            return True
        return False

    def print_payload(self):
        print('SESSION ' + str(self.session_number))
        for p in self.pkts:
            print(p.payload)
        print("\n\n")


def parseTCPConnection(direction, data):
    global sessions_count
    global tcp_sessions
    global last_pkt

    tcp_pkt = IP(data).getlayer(1)

    tcp_pkt.dport = tcp_pkt.fields['dport']
    tcp_pkt.sport = tcp_pkt.fields['sport']

    tcp_pkt.direction = direction

    last_pkt = tcp_pkt

    added = False

    for tcp_session in tcp_sessions:
        added |= tcp_session.add_if_match(tcp_pkt)
    if added == 0:
        sessions_count += 1
        tcp_sessions.append(TCPSession(tcp_pkt, sessions_count))
        debug('New session ' + str(sessions_count))

    for tcp_session in tcp_sessions:
        tcp_session.print_payload()


def common_process(payload, direction):
    global common_count
    data = payload.get_payload()
    pkt = IP(data)

    debug('--------------------------------')

    if pkt.proto == 0x06:  # TCP
        parseTCPConnection(direction, data)

        pkt = pkt.getlayer(1)
        common_count += 1
        debug(str(common_count) + (">>>" if direction == DIRECTION_INPUT else "<<<") + str(pkt.fields))
        debug(pkt.fields['flags'])
        debug("DATA:" + str(pkt.payload))


def process_input(payload):
    direction = DIRECTION_INPUT
    data = payload.get_payload()

    common_process(payload, direction)

    if static_filter(direction, data):
        payload.accept()
    else:
        payload.drop()


def process_output(payload):
    direction = DIRECTION_OUTPUT
    data = payload.get_payload()

    common_process(payload, direction)

    payload.accept()


def debug(s):
    global debug_enabled
    if debug_enabled:
        print("[DEBUG] " + str(s))


def static_filter(direction, data):
    global common_count
    pkt = IP(data)
    proto = pkt.proto
    #    print(data)
    #    print(pkt.fields)
    verdict = False

    if proto is 0x01:
        verdict = False

    elif proto is 0x06:

        pkt = pkt.getlayer(1)

        if pkt.fields['dport'] == 9090:
            verdict = True
        else:
            verdict = True

    else:
        verdict = False

    return verdict


def start_output():
    os.system("iptables -t mangle -I POSTROUTING -s 192.168.2.15 -j NFQUEUE --queue-num 1")

    q = netfilterqueue.NetfilterQueue()
    q.bind(1, process_output)

    try:
        print('starting output')
        q.run()
    except:
        print('exiting output')
        q.unbind()
        os.system("iptables -t mangle -D POSTROUTING -s 192.168.2.15 -j NFQUEUE --queue-num 1")
        sys.exit(1)


def start_input():
    os.system("iptables -t raw -I PREROUTING -d 192.168.2.15 -j NFQUEUE --queue-num 0")
    # os.system("iptables -t mangle -I POSTROUTING -s 192.168.2.15 -j NFQUEUE --queue-num 0")

    q = netfilterqueue.NetfilterQueue()
    q.bind(0, process_input)

    try:
        print('starting input')
        q.run()
    except:
        print('exiting input')
        q.unbind()
        os.system("iptables -t raw -D PREROUTING -d 192.168.2.15  -j NFQUEUE --queue-num 0")
        sys.exit(1)


def main():
    os.system("iptables -t nat -F")
    os.system("iptables -t mangle -F")

    output_thread = threading.Thread(target=start_output)
    output_thread.start()

    start_input()

    sys.exit(1)


main()
