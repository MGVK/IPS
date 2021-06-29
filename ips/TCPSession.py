from ips.logger import Logger
from multiprocessing import Manager


class TCPSession(object):

    def __init__(self, pkt, number):
        self.length = 0
        if not hasattr(self, 'pkts'):
            self.pkts = list()
        self.pkts.append(pkt)
        self.session_number = number
        self.valid = True

    def add_if_match(self, tcp_pkt):
        # debug(type(pkt))
        if tcp_pkt is not None and (len(self.pkts) == 0
                                    or self.pkts[-1].answers(tcp_pkt)
                                    or tcp_pkt.answers(self.pkts[-1])
                                    or tcp_pkt.ack == self.pkts[-1].ack
                                    or tcp_pkt.seq == self.pkts[-1].seq
                                    or tcp_pkt.seq == self.pkts[-1].ack):
            self.pkts.append(tcp_pkt)
            self.length += len(str(tcp_pkt.payload))
            # Logger.debug("LEN: "+str(self.length))
            # Logger.debug(str(self.session_number) + ">>>" +str(tcp_pkt.payload))
            # self.print_payload()
            return self.session_number
        return 0

    def print_payload(self):
        print('SESSION ' + str(self.session_number))
        for p in self.pkts:
            print(str(p))
        print("\n\n")

    def get_pairs(self):
        for p in self.pkts:
            pass
