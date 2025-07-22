import socket

# Use the Tailscale IP of the server machine
SERVER_IP = "100.102.137.18"  # Change this to your Tailnet IP
PORT = 5000  # Any free port

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, PORT))
server_socket.listen(1)

print(f"Server listening on {SERVER_IP}:{PORT}")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

while True:
    data = conn.recv(1024)
    if not data:
        break
    print(f"Received: {data.decode()}")
    conn.sendall(b"Message received!")

conn.close()
