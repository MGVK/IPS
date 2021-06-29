from ips.TCPSession import TCPSession
from ips.logger import Logger


class TCPParser:

    @staticmethod
    def parseTCPConnection(direction, data, ip_pkt, tcp_pkt, tcp_sessions,ses_counter):
        # global sessions_count
        # debug('parse tcp ' + str(direction))

        tcp_pkt.dport = tcp_pkt.fields['dport']
        tcp_pkt.sport = tcp_pkt.fields['sport']

        tcp_pkt.direction = direction

        session_number = 0

        for tcp_session in tcp_sessions:
            session_number = tcp_session.add_if_match(tcp_pkt)

        if not session_number:
            tcp_sessions.append(TCPSession(tcp_pkt, len(tcp_sessions)))
            Logger.debug('New session ' + str(len(tcp_sessions)))
            ses_counter.inc()

        return session_number
        # for tcp_session in tcp_sessions:
        # tcp_session.print_payload()