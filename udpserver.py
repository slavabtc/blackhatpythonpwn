# udp_server.py
import socket

bind_host = "127.0.0.1"
bind_port = 9997

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind_host, bind_port))
print("UDP server listening on", bind_host, bind_port)

while True:
    data, addr = sock.recvfrom(4096)
    print("From", addr, ":", data.decode())
    sock.sendto(b"PONG: " + data, addr)