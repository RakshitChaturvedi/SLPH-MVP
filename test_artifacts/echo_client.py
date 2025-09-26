import socket
import time

HOST = '127.0.0.1'
PORT = 12345
MESSAGE = b"hello from the python client"

time.sleep(1)

print(f"[*] Client connecting to {HOST}:{PORT}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"[*] Sending: {MESSAGE.decode('utf-8')}")
    s.sendall(MESSAGE)
    data = s.recv(1024)
    print(f"[*] Received echo: {data.decode('utf-8')}")

print("[*] Client finished.")