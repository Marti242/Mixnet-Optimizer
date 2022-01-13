from socket import socket
from socket import AF_INET
from socket import SOCK_DGRAM


def send_packet(packet: bytes, next_address: int):
    with socket(family=AF_INET, type=SOCK_DGRAM) as client:
        client.sendto(packet, ('127.0.0.1', next_address))
