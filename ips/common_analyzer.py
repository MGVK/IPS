import re

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ips.Constants import Constants
from ips.logger import Logger
from ips.parser import TCPParser
from netfilterqueue import Packet


class CommonProcess:

    @staticmethod
    def common_process(payload, direction, packets, tcp_sessions, cb_listener, callbacks):

        CommonProcess.common_worker(payload, direction, packets, tcp_sessions, cb_listener, callbacks)

    @staticmethod
    def common_worker(payload: Packet, direction, packets: list, tcp_sessions, cb_listener, callbacks: list):

        data = payload.get_payload()
        pkt = IP(data)
        tcp_pkt = None
        allow = False

        if pkt.proto == 0x06:  # TCP

            tcp_pkt = pkt.getlayer(1)

            allow = CommonProcess.static_filter(data, ip_pkt=pkt, tcp_pkt=tcp_pkt, direction=direction)

            TCPParser.parseTCPConnection(direction, data, pkt, tcp_pkt, tcp_sessions)

        else:

            allow = CommonProcess.static_filter(data, ip_pkt=pkt, direction=direction)
        # payload.accept()

        # cb_id = random.randint(1,99999999999999)
        # data = {'verdict': allow,
        #         'ip_pkt': pkt,
        #         'tcp_pkt': tcp_pkt,
        #         'direction': direction,
        #         'ready': False}
        #
        # packets.append(data)

        # while cb_id not in callbacks:
        #     cb_listener.listen()

        # Logger.debug("action: " + str(data['action']))

        # if callbacks[cb_id]:
        #     payload.accept()
        # else:
        #     payload.deny()

        allow = False
        if allow:
            Logger.debug("Accepted")
            payload.accept()
        else:
            Logger.debug("Dropped!!!")
            payload.drop()

        return payload

    @staticmethod
    def static_filter(data, ip_pkt, tcp_pkt: TCP = None, direction=None):
        global common_count
        proto = ip_pkt.proto
        #    print(data)
        #    print(pkt.fields)
        verdict = True

        if proto is 0x01:
            verdict = False

        elif proto is 0x06:

            if direction == Constants.DIRECTION_INPUT and tcp_pkt.fields['dport'] == 8080:
                verdict = True
            else:
                verdict = True

            Logger.debug(tcp_pkt.payload)
            if tcp_pkt.haslayer(Raw):

                # filter 1=1
                r = re.search(r'(1(%3D|=)1)', str(tcp_pkt.payload.load.decode("utf-8")))
                if r is not None :
                    Logger.debug("Found "+str(r.groups()))
                    return False


        else:
            verdict &= False

        return verdict
