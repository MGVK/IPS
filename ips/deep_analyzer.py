from multiprocessing.context import Process

from ips.logger import Logger


class AnalysisProcessor(Process):

    def __init__(self, pairs, sessions, packets, **kwargs):
        super(AnalysisProcessor, self).__init__()
        self._work = False
        self.pairs = pairs
        self.sessions = sessions
        self.packets = packets
        # self.pkt_listener = pkt_listener
        # self.cb_proxy = cb_proxy

    def run(self):
        Logger.info('starting analysis')

        last_pkt = 0
        self._work = True
        while self.is_enabled():
            # self.pkt_listener.listen()
            self.packets_ = self.packets[last_pkt:]
            last_pkt += len(self.packets_)
            for result in self.packets_:

                # print(result)

                ip_pkt = result['ip_pkt']
                direction = result['direction']
                # cb_id = result['cb_id']


                # debug(str(executor_number) + (">>>" if direction == DIRECTION_INPUT else "<<<") + str(ip_pkt.payload))

                # if 'tcp_pkt' in result:
                # tcp_pkt = result['tcp_pkt']
                # if not tcp_pkt is None:
                # debug("FLAGS:" + str(tcp_pkt.fields['flags']))
                # debug("DATA:" + str(tcp_pkt.payload))

                # if result['verdict']:
                #     self.cb_proxy[cb_id] = True
                # else:
                #     self.cb_proxy[cb_id] = False

                # executor_number += 1

    def is_enabled(self):
        return self._work

    def stop(self):
        self._work = False
