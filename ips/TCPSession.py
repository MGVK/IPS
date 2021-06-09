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

    def get_pairs(self):
        for p in self.pkts:
            pass