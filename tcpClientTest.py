import socket

def main():
    target_host = "127.0.0.1"   
    target_port = 9998


    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    client.connect((target_host, target_port))
    print(f"[*] Connected to {target_host}:{target_port}")


    test_data = "Hello from TCP client!"
    client.send(test_data.encode())


    response = client.recv(4096)
    print(f"[*] Received from server: {response.decode()}")


    client.close()

if __name__ == "__main__":
    main()