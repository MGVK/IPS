import re

from netfilterqueue import Packet
from prometheus_client import Counter
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ips.Constants import Constants
from ips.logger import Logger
from ips.parser import TCPParser


class CommonProcess:

    @staticmethod
    def common_process(payload,
                       packets,
                       tcp_sessions,
                       cb_listener,
                       callbacks,
                       pkt_counter,
                       ses_counter,
                       bad_sessions):

        CommonProcess.common_worker(payload,
                                    packets,
                                    tcp_sessions,
                                    cb_listener,
                                    callbacks,
                                    pkt_counter,
                                    ses_counter,
                                    bad_sessions)

    @staticmethod
    def common_worker(payload: Packet,
                      packets: list,
                      tcp_sessions,
                      cb_listener,
                      callbacks: list,
                      pkt_counter: Counter,
                      ses_counter: Counter,
                      bad_sessions: list):

        data = payload.get_payload()
        pkt = IP(data)

        direction = Constants.DIRECTION_INPUT if pkt.fields['dst'] == '192.168.2.15' else Constants.DIRECTION_OUTPUT
        tcp_pkt = None
        allow = True
        t = 1.5
        ave = 0
        sum = 0
        port = 0
        proto = 'other'
        session_number=None

        if pkt.proto == 0x06:  # TCP

            tcp_pkt = pkt.getlayer(1)
            port = tcp_pkt.fields['dport']
            proto = 'TCP'

            good_sessions = 0

            for s in tcp_sessions:
                if s.valid:
                    sum += s.length
                    good_sessions += 1
            ave = sum / good_sessions if good_sessions > 0 else sum

            Logger.debug("AVE: " + str(ave))
            Logger.debug("COUNT: " + str(good_sessions))
            Logger.debug("sum" + str(sum))

            session_number = TCPParser.parseTCPConnection(direction, data, pkt, tcp_pkt, tcp_sessions, ses_counter)
            # Logger.info("curr: "+str(tcp_sessions[session_number].length))

            if ave != 0 and abs(tcp_sessions[session_number].length / ave) > t:
                Logger.debug("!!! " + str(abs(tcp_sessions[session_number].length / ave)))
                allow = False

            # allow = CommonProcess.static_filter(data, ip_pkt=pkt, tcp_pkt=tcp_pkt, direction=direction)


        else:

            allow = CommonProcess.static_filter(data, ip_pkt=pkt, direction=direction)

        if allow:
            Logger.debug("Accepted")
            pkt_counter.labels(protocol=pkt.proto, action='accept', port=port, direction=direction).inc()
            payload.accept()
        else:
            Logger.debug("Dropped!!!")
            pkt_counter.labels(protocol=pkt.proto, action='drop', port=port, direction=direction).inc()
            payload.drop()
            if session_number is not None:
                tcp_sessions[session_number].valid = False

        return payload

    # @staticmethod
    # def extractURL(tcp_pkt:TCP):
    #     if tcp_pkt.haslayer(Raw):
    #         r = re.search(r'\w+\s/([^\s]+)',str(tcp_pkt.payload.load.decode("utf-8")))
    #         if r is not None and len(r.groups())>0:
    #             return r.groups()[0]

    @staticmethod
    def static_filter(data, ip_pkt, tcp_pkt: TCP = None, direction=None):
        global common_count
        proto = ip_pkt.proto
        #    print(data)
        #    print(pkt.fields)
        verdict = True

        if proto is 0x01:
            verdict = False
        elif proto is 0x17:
            verdict = True
        elif proto is 0x06:

            if direction == Constants.DIRECTION_INPUT and tcp_pkt.fields['dport'] == 8080:
                verdict = True
            elif direction == Constants.DIRECTION_INPUT and tcp_pkt.fields['dport'] == 8000:
                verdict = False
            else:
                verdict = True

      #      Logger.debug(tcp_pkt.payload)
      #      if tcp_pkt.haslayer(Raw):

                # filter 1=1
#                r = re.search(r'(1(%3D|=)1)', str(tcp_pkt.payload.load.decode("utf-8")))
 #               if r is not None:
  #                  Logger.debug("Found " + str(r.groups()))
   #                 return False


        else:
            verdict &= False

        return verdict
