import socket

from packet_sniffer.packet_sniffer import IPHeader, TCPPacket, EtherHeader, TCPHeader, TCPFlags, IPFlags

HOST = "172.28.208.1"  # wsl

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive a package

while True:
    recv = s.recv(4096)
    frame = recv[0]

    print(frame)
    EtherHeader(frame).dump(1)
    IPHeader(frame).dump(1)

# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
