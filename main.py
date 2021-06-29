import logging

from prometheus_client import start_http_server, Counter

from ips.Constants import Constants
from ips.common_analyzer import CommonProcess
from ips.deep_analyzer import AnalysisProcessor
from ips.logger import Logger

l = logging.getLogger("scapy.runtime")
l.setLevel(49)

import netfilterqueue
from scapy.all import *

common_count = 0
sessions_count = 0

last_pkt = None

executors = list()
executor = None

packets = None
packets_listener = None
tcp_sessions = None
cb_listener = None
callbacks = None
pkt_counter = None
counter_drop = None
bad_sessions = None
global_direction = None
ses_counter = None

def process_traffic(payload:netfilterqueue.Packet):
    global packets
    global tcp_sessions
    global cb_listener
    global callbacks
    global pkt_counter
    global ses_counter

    Logger.debug("NEW PACKET!")

    CommonProcess.common_process(payload,
                                 packets,
                                 tcp_sessions,
                                 cb_listener,
                                 callbacks,
                                 pkt_counter,
                                 ses_counter,
                                 bad_sessions)


# @ray.remote
def start(m):
    global packets
    global packets_listener
    global tcp_sessions
    global cb_listener
    global callbacks
    global pkt_counter
    global bad_sessions
    global global_direction
    global ses_counter

    direction = m[0]
    global_direction = direction
    n = m[1]
    sum = m[2]
    packets = m[3]
    tcp_sessions = m[4]
    cb_listener = m[5]
    callbacks = m[6]
    local_ip = m[7]
    pkt_counter = m[8]
    ses_counter = m[9]
    bad_sessions = list()

    # Logger.info("packets_" + direction + "_" + str(n))
    print("!!"+direction)

    if direction == Constants.DIRECTION_INPUT:

        cmd = ("iptables -t raw -I PREROUTING -d " + local_ip +
               " -m statistic --mode nth --every " + str(sum)
               + " --packet " + str(n) + " -j NFQUEUE --queue-num " + str(n))

        cmd2 = ("iptables -t raw -I PREROUTING -d " + local_ip +
                " -m statistic --mode nth --every " + str(sum)
                + " --packet " + str(n) + " -j LOG --log-prefix 'INPUT!!!NFQUEUE" + str(n) + "of" + str(sum)
                + ">>>' --log-level 4")
        Logger.info(cmd)
        Logger.info(cmd2)
        os.system(cmd)
        # os.system(cmd2)

    else:

        # pkt_counter = Counter("packets_" + direction + "_" + str(n), "", ['protocol', 'port', 'action'])
        # Logger.info("packets_" + direction + "_" + str(n))

        # start_http_server(10000+n)

        cmd = ("iptables -t mangle -I POSTROUTING -s " + local_ip +
               " -m statistic --mode nth --every " + str(sum)
               + " --packet " + str(n) + " -j NFQUEUE --queue-num " + str(sum + n))

        cmd2 = ("iptables -t mangle -I POSTROUTING -s " + local_ip +
                " -m statistic --mode nth --every " + str(sum)
                + " --packet " + str(n) + "  -j LOG --log-prefix 'OUTPUT!!!NFQUEUE" + str(n) + "of" + str(sum)
                + ">>>' --log-level 4")
        Logger.info(cmd)
        Logger.info(cmd2)
        os.system(cmd)
        # os.system(cmd2)

    q = netfilterqueue.NetfilterQueue()
    q.bind(n if direction == Constants.DIRECTION_INPUT else n + sum, process_traffic)

    try:
        Logger.info('starting ' + ('input' if direction == Constants.DIRECTION_INPUT else 'output') + ' on ' + str(n))
        q.run()
    except:
        Logger.info('exiting ' + ('input' if direction == Constants.DIRECTION_INPUT else 'output') + ' on ' + str(n))
        q.unbind()
        clear_iptables(local_ip)
        sys.exit(1)


def clear_iptables(local_ip):
    os.system("iptables -t raw -D PREROUTING -d " + local_ip + "  -j NFQUEUE --queue-num 0")
    os.system("iptables -t mangle -D POSTROUTING -s " + local_ip + " -j NFQUEUE --queue-num 1")
    os.system("iptables -t raw -F")
    os.system("iptables -t mangle -F")


def init_iptables(local_ip):
    os.system("iptables -t raw -I PREROUTING -d " + local_ip + " -j LOG --log-prefix 'INPUT!!!IPS>>>' --log-level 4")
    os.system(
        "iptables -t mangle -I POSTROUTING -s " + local_ip + " -j LOG --log-prefix 'OUTPUT!!!IPS>>>' --log-level 4")


def main():
    local_ip = sys.argv[1]

    if not local_ip:
        sys.exit(1)

    clear_iptables(local_ip)
    # init_iptables(local_ip)
    process_count = 1

    # from multiprocessing import Manager
    # m = Manager()

    tcp_sessions_list = list()
    tcp_pairs_list = list()
    packets = list()
    callbacks = list()
    start_http_server(9000, addr='192.168.2.17')
    pkt_counter = Counter("packets", "", ['protocol', 'port', 'action', 'direction'])
    ses_counter = Counter("sessions", "")


    # pkt_proxy, pkt_listener = proxy.createProxy(packets)
    # cb_proxy, cb_listener = proxy.createProxy(callbacks)

    for d in [Constants.DIRECTION_INPUT, Constants.DIRECTION_OUTPUT]:
        r = range(0, process_count)
        for i in r:
            # proc = Process(target=start,
            #                args=([d, i, process_count,
            #                       packets, tcp_sessions_list, cb_listener, callbacks, local_ip],),
            #                name=str(d) + "_" + str(i))
            # proc.start()
            proc = Thread(target=start,
                           args=([[d, i, process_count,
                                  packets, tcp_sessions_list, cb_listener, callbacks, local_ip,pkt_counter,
                                  ses_counter]]),
                           name=str(d) + "_" + str(i))
            proc.start()

    analysis_thread = AnalysisProcessor(tcp_pairs_list, tcp_sessions_list, packets)
    # analysis_thread.start()
    # start_input()
    # analysis_thread.stop()

    import time
    while True:
        time.sleep(1)

    # sys.exit(1)


main()
