import socket

HOST = '127.0.0.1'
PORT = 12345

print(f"[*] Echo server starting up on {HOST}:{PORT}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print("[*] Server is listening...")
    conn, addr = s.accept()
    with conn:
        print(f"[*] Connected by {addr}")
        data = conn.recv(1024)
        print(f"[*] Received: {data.decode('utf-8')}")
        conn.sendall(data)
        print("[*] Echoed data back to client.")

print("[*] Server shutting down.")