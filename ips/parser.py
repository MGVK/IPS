from ips.TCPSession import TCPSession
from ips.logger import Logger


class TCPParser:

    @staticmethod
    def parseTCPConnection(direction, data, ip_pkt, tcp_pkt, tcp_sessions,tcp_sessions_pairs=None):
        # global sessions_count
        # debug('parse tcp ' + str(direction))

        tcp_pkt.dport = tcp_pkt.fields['dport']
        tcp_pkt.sport = tcp_pkt.fields['sport']

        tcp_pkt.direction = direction

        last_pkt = tcp_pkt

        added = False

        for tcp_session in tcp_sessions:
            added |= tcp_session.add_if_match(tcp_pkt)

        if not added:
            tcp_sessions.append(TCPSession(tcp_pkt, len(tcp_sessions)))
            Logger.info('New session ' + str(len(tcp_sessions)))

        # for tcp_session in tcp_sessions:
        # tcp_session.print_payload()