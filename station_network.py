import socket
import threading
import os
from rejndael import aes
from message import (
    discover_tailscale_addresses,
    pack_key_gen_message, pack_text_message, pack_file_block_message, unpack_message,
    create_halfway_key, create_key, P, G
)


class StationNetwork:
    def __init__(self, message_callback=None, status_callback=None):
        """
        Initialize the network component

        Args:
            message_callback: Function to call when a message is received (args: hostname, message)
            status_callback: Function to call when connection status changes (args: hostname, status, error_message=None)
        """
        self.message_callback = message_callback or (lambda h, m: None)
        self.status_callback = status_callback or (lambda h, s, e=None: None)
        self.connections = {}  # {hostname: (socket, address)}
        self.listen_socket = None
        self.lock = threading.Lock()
        self.shared_keys = {}  # {hostname: key_bytes}
        self.secrets = {}  # {hostname: my_secret}
        self.file_buffers = {}  # {hostname: {filename: {block_number: data, ...}}}
        self.file_sizes = {}  # {hostname: {filename: total_size}}
        # Start listening
        self.start_listening()

    def start_listening(self):
        """Start listening for incoming connections"""
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow port reuse
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Try to bind to port 5000
            try:
                self.listen_socket.bind(('0.0.0.0', 5000))  # Bind to all interfaces
            except OSError as e:
                if e.errno == 98 or e.errno == 10048:  # Port already in use
                    raise Exception("Port 5000 is already in use. Make sure no other instance is running.")
                raise

            self.listen_socket.listen(5)

            # Start listener thread
            threading.Thread(target=self.accept_connections, daemon=True).start()

            # Get my address from Tailscale
            try:
                peers = discover_tailscale_addresses()
                my_hostname = socket.gethostname()
                if my_hostname in peers:
                    return f"{peers[my_hostname]}:5000"
            except:
                pass

            # Fallback to regular hostname
            host = socket.gethostbyname(socket.gethostname())
            return f"{host}:5000"

        except Exception as e:
            raise Exception(f"Could not start listening: {str(e)}")

    def accept_connections(self):
        """Accept incoming connections"""
        while True:
            try:
                client_socket, address = self.listen_socket.accept()
                # Try to find the hostname for this connection
                peers = discover_tailscale_addresses()
                hostname = None
                for h, ip in peers.items():
                    if ip == address[0]:
                        hostname = h
                        break

                if not hostname:
                    hostname = f"{address[0]}:{address[1]}"

                with self.lock:
                    if hostname not in self.connections:  # Only accept if not already connected
                        self.connections[hostname] = (client_socket, address)
                        self.status_callback(hostname, "connected")

                        # Start a thread to receive messages from this client
                        threading.Thread(target=self.receive_messages,
                                         args=(client_socket, hostname),
                                         daemon=True).start()
                    else:
                        client_socket.close()
            except Exception as e:
                print(f"Accept error: {e}")
                continue

    def connect_to_peer(self, hostname):
        """Connect to another peer using Tailscale"""
        import secrets
        try:
            # Check if we're already connected
            if hostname in self.connections:
                self.status_callback(hostname, "connected")
                return

            peers = discover_tailscale_addresses()
            if hostname not in peers:
                raise Exception(f"Peer {hostname} not found in Tailscale network.")
            ip = peers[hostname]
            port = 5000
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            try:
                sock.connect((ip, port))
                sock.settimeout(None)

            except socket.timeout:
                raise Exception("Connection timed out. Peer might be offline.")

            except ConnectionRefusedError:
                raise Exception("Peer is not online or not accepting connections")

            except Exception as e:
                raise Exception(f"Connection error: {str(e)}")

            with self.lock:
                if hostname not in self.connections:
                    self.connections[hostname] = (sock, (ip, port))
                    threading.Thread(target=self.receive_messages, args=(sock, hostname), daemon=True).start()
                    self.status_callback(hostname, "connected")
                    # Handshake: send own halfway kei
                    my_secret = secrets.randbits(128)
                    self.secrets[hostname] = my_secret
                    halfway_key = create_halfway_key(P, G, my_secret)
                    msg = pack_key_gen_message(halfway_key)
                    # handshake with len
                    sock.sendall(len(msg).to_bytes(4, 'big') + msg)
                    # print(f"[DEBUG] Sent KEY_GEN to {hostname}")
                else:
                    sock.close()
        except Exception as e:
            self.status_callback(hostname, "error", str(e))
            raise

    @staticmethod
    def recv_exact(sock, size):
        buf = bytearray()
        while len(buf) < size:
            chunk = sock.recv(size - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed")
            buf.extend(chunk)
        return buf

    def receive_messages(self, sock, hostname):
        """Receive messages from a specific connection"""
        while True:
            try:
                # data = sock.recv(4096)

                length_bytes = sock.recv(4)
                length = int.from_bytes(length_bytes, 'big')
                data = self.recv_exact(sock, length)
                if not data:
                    break
                msg = unpack_message(data)
                if not msg:
                    print(f"[WARN] Unknown/invalid message from {hostname}")
                    continue
                msg_type = msg.get('type')
                if msg_type == 'KEY_GEN':
                    # print(f"[DEBUG] Received KEY_GEN from {hostname}")

                    halfway_key = msg['halfway_key']

                    if hostname not in self.secrets:
                        import secrets as pysecrets
                        self.secrets[hostname] = pysecrets.randbits(128)

                        my_halfway = create_halfway_key(P, G, self.secrets[hostname])
                        reply = pack_key_gen_message(my_halfway)

                        sock.sendall(len(reply).to_bytes(4, 'big') + reply)
                        # print(f"[DEBUG] Sent KEY_GEN to {hostname} (in response)")
                    shared_key = create_key(P, self.secrets[hostname], halfway_key)
                    self.shared_keys[hostname] = shared_key
                    print(f"[INFO] Shared key established with {hostname} (handshake OK)")
                    # print(f"[DEBUG] shared_keys: {self.shared_keys}")
                elif msg_type == 'TEXT_MSG':
                    if hostname not in self.shared_keys:
                        print(f"[WARN] No shared key with {hostname}. Cannot decrypt message.")
                        continue
                    shared_key = self.shared_keys[hostname]
                    encrypted = msg['payload']
                    try:
                        decrypted = aes(bytearray(encrypted), cypher_type="aes_128", key=shared_key, decrypt=True)
                        self.message_callback(hostname, decrypted)
                    except Exception as e:
                        print(f"Decrypt error from {hostname}: {e}")
                elif msg_type == 'FILE_BLOCK':
                    # print(f'{msg=}')

                    fname = msg['file_name'][12:-2]  # get rid of byte representation
                    block_number = msg['block_number']
                    file_size = msg['file_size']
                    payload = msg['payload']

                    if hostname not in self.shared_keys:
                        print(f"[WARN] No shared key with {hostname}. Cannot decrypt file block.")
                        continue
                    shared_key = self.shared_keys[hostname]
                    try:
                        # print(f'{len(bytearray(payload))=}, {len(payload)=}')
                        decrypted_data = aes(bytearray(payload), cypher_type="aes_128", key=shared_key, decrypt=True)
                    except Exception as e:
                        print(f"File block decrypt error: {e}")
                        continue

                    # Buffer pentru blocuri
                    if hostname not in self.file_buffers:
                        self.file_buffers[hostname] = {}
                    if fname not in self.file_buffers[hostname]:
                        self.file_buffers[hostname][fname] = {}
                        self.file_sizes.setdefault(hostname, {})[fname] = file_size
                    self.file_buffers[hostname][fname][block_number] = decrypted_data

                    blocks = self.file_buffers[hostname][fname]
                    total_blocks = (file_size + 4095) // 4096

                    if len(blocks) == total_blocks:

                        with open(fname, 'w') as f:
                            for i in range(total_blocks):
                                f.write(blocks[i][2:-1])    # get rid of byte representation

                        print(f"[INFO] File '{fname}' received and reconstructed from {hostname}!")
                        self.message_callback(hostname, f"[File received: {fname}]")

                        del self.file_buffers[hostname][fname]
                        del self.file_sizes[hostname][fname]
                else:
                    print(f"[WARN] Received unknown message type from {hostname}: {msg_type}")
            except socket.error as e:
                print(f"Socket error with {hostname}: {e}")
                break
            except Exception as e:
                print(f"Unexpected error with {hostname}: {e}")
                break
        # Connection lost
        try:
            sock.close()
        except:
            pass
        with self.lock:
            if hostname in self.connections:
                del self.connections[hostname]
                self.status_callback(hostname, "disconnected")

    def send_message(self, hostname, message, msg_type='TEXT_MSG'):
        """Send message to a specific peer (text, key, or file block)"""

        if not message or hostname not in self.connections:
            return False

        try:
            with self.lock:
                if hostname not in self.connections:
                    return False

                sock, _ = self.connections[hostname]
                if msg_type == 'KEY_GEN':
                    msg = pack_key_gen_message(message)
                    sock.sendall(len(msg).to_bytes(4, 'big') + msg)

                    return True

                elif msg_type == 'TEXT_MSG':
                    if hostname not in self.shared_keys:
                        print(f"[WARN] No shared key with {hostname}. Cannot send encrypted message.")

                        return False

                    shared_key = self.shared_keys[hostname]
                    encrypted = aes(str(message), cypher_type="aes_128", key=shared_key)
                    msg = pack_text_message(encrypted)
                    sock.sendall(len(msg).to_bytes(4, 'big') + msg)

                    return True

                elif msg_type == 'FILE_BLOCK':
                    # message = (filename, payload_bytes, block_number, file_size)
                    fname, payload, block_number, file_size = message
                    if hostname not in self.shared_keys:
                        print(f"[WARN] No shared key with {hostname}. Cannot send file block.")

                        return False

                    shared_key = self.shared_keys[hostname]
                    encrypted = aes(str(payload), cypher_type="aes_128", key=shared_key)
                    # print(f'{encrypted=}, {len(encrypted)=}')

                    msg = pack_file_block_message((fname, encrypted, block_number, file_size))
                    sock.sendall(len(msg).to_bytes(4, 'big') + msg)

                    return True

                else:
                    print(f"[WARN] Unknown message type for send: {msg_type}")

                    return False
        except Exception as e:
            print(f"Error preparing/sending message for {hostname}: {e}")
            with self.lock:
                if hostname in self.connections:
                    del self.connections[hostname]
            self.status_callback(hostname, "disconnected")

            return False

    def get_connected_peers(self):
        """Get list of connected peer hostnames"""
        with self.lock:
            return list(self.connections.keys())

    def is_connected(self, hostname):
        """Check if connected to a specific peer"""
        return hostname in self.connections

    def send_file(self, hostname, filepath):
        """Send a file to a peer in encrypted blocks"""
        if not os.path.isfile(filepath):
            print(f"[ERROR] File not found: {filepath}")

            return False

        fname = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        block_size = 4096
        total_blocks = (filesize + block_size - 1) // block_size

        with open(filepath, 'rb') as f:
            for block_number in range(total_blocks):
                data = f.read(block_size)

                self.send_message(
                    hostname,
                    (fname, data, block_number, filesize),
                    msg_type='FILE_BLOCK'
                )
        print(f"[INFO] File '{fname}' sent to {hostname} in {total_blocks} blocks.")

        return True
