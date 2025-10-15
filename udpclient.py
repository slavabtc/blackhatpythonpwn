import socket

target_host = "127.0.0.1"
target_port = 9997

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(3.0)  # seconds

try:
    client.sendto(b"PING AAAABBBBCCC test data", (target_host, target_port))
    data, addr = client.recvfrom(4096)
    print("Received:", data.decode())
except socket.timeout:
    print("No response received within timeout.")
finally:
    client.close()
