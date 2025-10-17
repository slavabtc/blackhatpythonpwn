#!/usr/bin/env python3
import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

# Run a local command and return its output (stdout/stderr)
def execute(cmd: str) -> str:
    cmd = cmd.strip()
    if not cmd:
        return ""
    try:
        out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
        return out.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors="ignore")
    except Exception as e:
        return f"Execution error: {e}\n"

class NetCat:
    def __init__(self, args, buffer: bytes = b""):
        self.args = args
        self.buffer = buffer or b""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    # Client mode
    def send(self):
        try:
            self.socket.connect((self.args.target, self.args.port))
        except Exception as e:
            print(f"[!] Connect failed: {e}")
            return

        # If we got stdin data (echo/pipe), send it first
        if self.buffer:
            try:
                self.socket.sendall(self.buffer)
            except Exception as e:
                print(f"[!] Initial send failed: {e}")
                self.socket.close()
                return

        try:
            while True:
                # Read server response (if any)
                response = b""
                self.socket.settimeout(0.2)
                try:
                    while True:
                        chunk = self.socket.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if len(chunk) < 4096:
                            break
                except (BlockingIOError, TimeoutError, socket.timeout):
                    pass
                finally:
                    self.socket.settimeout(None)

                if response:
                    print(response.decode(errors="ignore"), end="")

                # Interactive input
                try:
                    line = input("> ")
                except EOFError:
                    # Ctrl-D: close gracefully
                    break
                self.socket.sendall((line + "\n").encode())
        except KeyboardInterrupt:
            print("\n[!] User terminated.")
        finally:
            self.socket.close()

    # Server mode
    def listen(self):
        bind_addr = self.args.target or "0.0.0.0"
        try:
            self.socket.bind((bind_addr, self.args.port))
        except OSError as e:
            print(f"[!] Failed to bind to {bind_addr}:{self.args.port} -> {e}")
            print("[!] Use a local IP assigned to this host, or 0.0.0.0 to bind all interfaces.")
            sys.exit(1)

        self.socket.listen(5)
        print(f"[*] Listening on {bind_addr}:{self.args.port}")

        while True:
            client_socket, client_addr = self.socket.accept()
            print(f"[*] Accepted connection from {client_addr[0]}:{client_addr[1]}")
            t = threading.Thread(target=self.handle, args=(client_socket,))
            t.daemon = True
            t.start()

    # Per-connection handler (server-side)
    def handle(self, client_socket: socket.socket):
        with client_socket as sock:
            try:
                if self.args.execute:
                    output = execute(self.args.execute) or ""
                    sock.sendall(output.encode(errors="ignore"))

                elif self.args.upload:
                    file_buffer = b""
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        file_buffer += data
                    try:
                        with open(self.args.upload, "wb") as f:
                            f.write(file_buffer)
                        msg = f"Saved file {self.args.upload}\n"
                    except Exception as e:
                        msg = f"Failed to save file: {e}\n"
                    sock.sendall(msg.encode(errors="ignore"))

                elif self.args.command:
                    # Simple interactive shell
                    while True:
                        sock.sendall(b"BHP: #> ")
                        cmd_buffer = b""
                        while b"\n" not in cmd_buffer:
                            chunk = sock.recv(64)
                            if not chunk:
                                return  # client closed
                            cmd_buffer += chunk
                        cmd = cmd_buffer.decode(errors="ignore").strip()
                        if not cmd:
                            continue
                        resp = execute(cmd)
                        sock.sendall(resp.encode(errors="ignore"))
                else:
                    # Default behavior: echo back what we get
                    data = sock.recv(4096)
                    if data:
                        sock.sendall(data)
            except Exception as e:
                print(f"[!] Client handler error: {e}")
                return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BHP Net Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Listen (command shell)
              netcat.py -t 0.0.0.0 -p 5555 -l -c

              # Listen and save uploaded data to file
              netcat.py -t 0.0.0.0 -p 5555 -l -u=mytext.txt

              # Listen and execute command, send output
              netcat.py -t 0.0.0.0 -p 5555 -l -e="cat /etc/passwd"

              # Send data from stdin to remote
              echo 'ABC' | ./netcat.py -t 192.168.178.50 -p 5555

              # Connect interactively to remote
              netcat.py -t 192.168.178.50 -p 5555
        """),
    )
    parser.add_argument("-c", "--command", action="store_true", help="command shell")
    parser.add_argument("-e", "--execute", help="execute specified command")
    parser.add_argument("-l", "--listen", action="store_true", help="listen")
    parser.add_argument("-p", "--port", type=int, default=5555, help="specified port")
    parser.add_argument("-t", "--target", default="0.0.0.0", help="IP address (use 0.0.0.0 to bind all interfaces)")
    parser.add_argument("-u", "--upload", help="upload file path to write to (server mode)")

    args = parser.parse_args()

    # For client mode, read stdin as bytes (supports piping)
    if args.listen:
        buffer = b""
    else:
        try:
            buffer = sys.stdin.buffer.read()
        except Exception:
            buffer = b""

    nc = NetCat(args, buffer)
    nc.run()
