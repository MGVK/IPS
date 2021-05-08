import concurrent
import logging

from scapy.layers.inet import IP, ICMP, TCP
import threading
from scapy.all import wrpcap
from concurrent.futures.thread import ThreadPoolExecutor

l = logging.getLogger("scapy.runtime")
l.setLevel(49)

import os, sys, netfilterqueue, socket
from scapy.all import *

DIRECTION_INPUT = 'input'
DIRECTION_OUTPUT = 'output'

common_count = 0
sessions_count = 0

info_enabled = True
debug_enabled = 1
output_enabled = 0

last_pkt = None

tcp_sessions = list()
executors = list()
executor = None


class TCPSession(object):

    def __init__(self, pkt, number):
        if not hasattr(self, 'pkts'):
            self.pkts = list()
        self.pkts.append(pkt)
        self.session_number = number

    def add_if_match(self, tcp_pkt):
        # debug(type(pkt))
        if tcp_pkt is not None and (len(self.pkts) == 0
                                    or self.pkts[-1].answers(tcp_pkt)
                                    or tcp_pkt.answers(self.pkts[-1])
                                    or tcp_pkt.ack == self.pkts[-1].ack
                                    or tcp_pkt.seq == self.pkts[-1].seq
                                    or tcp_pkt.seq == self.pkts[-1].ack):
            self.pkts.append(tcp_pkt)
            return self.session_number
        return 0

    def print_payload(self):
        print('SESSION ' + str(self.session_number))
        for p in self.pkts:
            print(p.payload)
        print("\n\n")


def parseTCPConnection(direction, data, ip_pkt, tcp_pkt):
    # global sessions_count
    global tcp_sessions
    global last_pkt

    # debug('parse tcp ' + str(direction))

    tcp_pkt.dport = tcp_pkt.fields['dport']
    tcp_pkt.sport = tcp_pkt.fields['sport']

    tcp_pkt.direction = direction

    last_pkt = tcp_pkt

    added = False

    # with concurrent.futures.ThreadPoolExecutor() as tcp_parser_executor:
    #     futures = []
    #     for tcp_session in tcp_sessions:
    #         futures.append(
    #             tcp_parser_executor.submit(tcp_session.add_if_match, tcp_pkt=tcp_pkt)
    #         )
    #
    #     if added == 0:
    #         # sessions_count += 1
    #         tcp_sessions.append(TCPSession(tcp_pkt, len(tcp_sessions)))
    #         # info('New session ' + str(sessions_count))
    #     # else:
    # info('Session ' + str(added))

    for tcp_session in tcp_sessions:
        added |= tcp_session.add_if_match(tcp_pkt)

    # for tcp_session in tcp_sessions:
    # tcp_session.print_payload()


def common_worker(payload, direction):
    global common_count
    data = payload.get_payload()
    pkt = IP(data)
    tcp_pkt = None
    allow = False

    if pkt.proto == 0x06:  # TCP

        tcp_pkt = pkt.getlayer(1)

        if direction == DIRECTION_INPUT and not static_filter(direction, data, ip_pkt=pkt, tcp_pkt=tcp_pkt):
            allow = False

        parseTCPConnection(direction, data, pkt, tcp_pkt)

    else:

        if direction == DIRECTION_INPUT and not static_filter(direction, data, ip_pkt=pkt):
            allow = False

    allow = True

    payload.accept()

    return {
        'verdict': allow,
        'ip_pkt': pkt,
        'tcp_pkt': tcp_pkt,
        'original_payload': payload,
        'direction': direction}


def demo_worker(payload):
    # f = IP(payload.get_payload())
    payload.accept()


def common_process(payload, direction):
    global executor
    global executors
    # global common_count
    # loc_common_count = common_count + 1
    # common_count = loc_common_count
    # executors[str(loc_common_count)] = executor.submit(common_worker, payload=payload, direction=direction)
    # executors.append(executor.submit(common_worker, payload=payload, direction=direction))
    # debug("added executor " + str(common_count))
    # debug(executors)
    # executor.submit(demo_worker, payload=payload)
    # threading.Thread(target=demo_worker, args=[payload]).start()
    payload.accept()


def process_input(payload):
    direction = DIRECTION_INPUT
    common_process(payload, direction)


def process_output(payload):
    direction = DIRECTION_OUTPUT
    common_process(payload, direction)


class AnalysisThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self._work = False

    def run(self):
        global executors
        executor_number = 1
        info('starting analysis')

        self._work = False
        while self.is_enabled():
            # debug('### waiting for executor ' + str(executor_number))
            while len(executors) <= executor_number:
                pass
            # debug('### arrived executor ' + str(executor_number))
            executor = executors[executor_number]
            result = next(concurrent.futures.as_completed([executor])).result()
            # debug('### completed executor ' + str(executor_number))
            ip_pkt = result['ip_pkt']
            direction = result['direction']
            orig_peayload = result['original_payload']

            # debug(str(executor_number) + (">>>" if direction == DIRECTION_INPUT else "<<<") + str(ip_pkt.payload))

            # if 'tcp_pkt' in result:
            # tcp_pkt = result['tcp_pkt']
            # if not tcp_pkt is None:
            # debug("FLAGS:" + str(tcp_pkt.fields['flags']))
            # debug("DATA:" + str(tcp_pkt.payload))

            if result['verdict']:
                orig_peayload.accept()
            else:
                orig_peayload.drop()

            executor_number += 1

    def is_enabled(self):
        return self._work

    def stop(self):
        self._work = False


def output(prefix, s):
    global output_enabled
    if output_enabled:
        print(prefix, s)


def info(s):
    global info_enabled
    if info_enabled:
        output("[INFO] ", str(s))


def debug(s):
    global debug_enabled
    if debug_enabled:
        output("[DEBUG] ", str(s))


def static_filter(direction, data, ip_pkt, tcp_pkt=None):
    global common_count
    proto = ip_pkt.proto
    #    print(data)
    #    print(pkt.fields)
    verdict = False

    if proto is 0x01:
        verdict = False

    elif proto is 0x06:

        if tcp_pkt.fields['dport'] == 9090:
            verdict = True
        else:
            verdict = True

    else:
        verdict = False

    return verdict


def start_output():
    q = netfilterqueue.NetfilterQueue()
    q.bind(1, process_output)

    try:
        info('starting output')
        q.run()
    except:
        info('exiting output')
        q.unbind()
        clear_iptables()
        sys.exit(1)


def start_input():
    # os.system("iptables -t mangle -I POSTROUTING -s 192.168.2.15 -j NFQUEUE --queue-num 0")

    q = netfilterqueue.NetfilterQueue()
    q.bind(0, process_input)

    try:
        info('starting input')
        q.run()
    except:
        info('exiting input')
        q.unbind()
        clear_iptables()
        sys.exit(1)


def clear_iptables():
    os.system("iptables -t raw -D PREROUTING -d 192.168.2.15  -j NFQUEUE --queue-num 0")
    os.system("iptables -t mangle -D POSTROUTING -s 192.168.2.15 -j NFQUEUE --queue-num 1")
    os.system("iptables -t raw -F")
    os.system("iptables -t mangle -F")


def init_iptables():
    os.system("iptables -t raw -I PREROUTING -d 192.168.2.15 -j NFQUEUE --queue-num 0")
    os.system("iptables -t mangle -I POSTROUTING -s 192.168.2.15 -j NFQUEUE --queue-num 1")


def main():
    clear_iptables()
    init_iptables()

    global executor
    executor = ThreadPoolExecutor()

    output_thread = threading.Thread(target=start_output)
    output_thread.start()

    analysis_thread = AnalysisThread()
    analysis_thread.start()

    start_input()
    analysis_thread.stop()

    sys.exit(1)


main()
