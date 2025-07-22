import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from message import discover_tailscale_addresses
from station_network import StationNetwork


class StationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Station Communication")
        self.root.geometry("1000x700")

        self.selected_peer = None

        # Create network handler
        self.network = StationNetwork(
            message_callback=self.on_message_received,
            status_callback=self.on_connection_status
        )

        # Create and set up the GUI
        self.setup_gui()

        # Show my address
        try:
            host = self.network.start_listening()
            self.my_address.config(text=host)
        except Exception as e:
            messagebox.showerror("Error", str(e))

        # Start Tailscale discovery
        self.update_peers()

    def setup_gui(self):
        # Main container
        main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel for peers
        left_panel = ttk.Frame(main_container)
        main_container.add(left_panel, weight=1)

        # Peers list
        ttk.Label(left_panel, text="Online Peers").pack(pady=5)
        self.peers_list = ttk.Treeview(left_panel, selectmode='browse', show='tree')
        self.peers_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.peers_list.bind('<<TreeviewSelect>>', self.on_peer_selected)

        # Refresh button
        ttk.Button(left_panel, text="Refresh Peers", command=self.update_peers).pack(pady=5)

        # Right panel for chat
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, weight=3)

        # My address display
        addr_frame = ttk.Frame(right_panel)
        addr_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(addr_frame, text="My Address:").pack(side=tk.LEFT)
        self.my_address = ttk.Label(addr_frame, text="Not listening")
        self.my_address.pack(side=tk.LEFT, padx=5)

        # Selected peer display
        self.peer_label = ttk.Label(right_panel, text="Select a peer to start chatting")
        self.peer_label.pack(pady=5)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(right_panel, wrap=tk.WORD, height=20)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chat_display.config(state=tk.DISABLED)

        # Message input frame
        input_frame = ttk.Frame(right_panel)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        # Message input
        self.msg_entry = ttk.Entry(input_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())

        # Send button
        self.send_btn = ttk.Button(input_frame, text="Send", command=self.send_message, state=tk.DISABLED)
        self.send_btn.pack(side=tk.RIGHT)

        # File send button
        self.file_btn = ttk.Button(input_frame, text="Send File", command=self.send_file, state=tk.DISABLED)
        self.file_btn.pack(side=tk.RIGHT, padx=(0, 5))

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, padx=5, pady=5)

    def on_message_received(self, hostname, message):
        """Callback for when a message is received"""
        if isinstance(message, str) and message.startswith('[File received:'):
            self.add_message(f"[{hostname}] {message}")
        else:
            self.add_message(f"[{hostname}] {message}")

    def on_connection_status(self, hostname, status, error_message=None):
        """Callback for connection status changes"""
        if status == "connected":
            self.add_message(f"Connected to {hostname}")
            try:
                self.peers_list.item(hostname, text=f"{hostname} (Connected)")
            except:
                pass
            if hostname == self.selected_peer:
                self.peer_label.config(text=f"Chatting with: {hostname} (Connected)")
                self.send_btn.config(state=tk.NORMAL)
                self.file_btn.config(state=tk.NORMAL)
        elif status == "disconnected":
            self.add_message(f"Disconnected from {hostname}")
            try:
                self.peers_list.item(hostname, text=f"{hostname} (Available)")
            except:
                pass
            if hostname == self.selected_peer:
                self.peer_label.config(text=f"Disconnected from {hostname}")
                self.send_btn.config(state=tk.DISABLED)
                self.file_btn.config(state=tk.DISABLED)
        elif status == "error":
            if error_message:
                self.add_message(f"Error with {hostname}: {error_message}")
            if hostname == self.selected_peer:
                self.send_btn.config(state=tk.DISABLED)
                self.file_btn.config(state=tk.DISABLED)

    def update_peers(self):
        """Update the list of available Tailscale peers"""
        try:
            peers = discover_tailscale_addresses()

            # Clear current list
            self.peers_list.delete(*self.peers_list.get_children())

            # Add peers to the list
            connected_peers = self.network.get_connected_peers()
            for hostname, ip in peers.items():
                status = "Connected" if hostname in connected_peers else "Available"
                self.peers_list.insert('', 'end', hostname, text=f"{hostname} ({status})")

        except Exception as e:
            self.status_var.set(f"Error updating peers: {str(e)}")

    def on_peer_selected(self, event):
        """Handle peer selection from the list"""
        selection = self.peers_list.selection()
        if not selection:
            self.selected_peer = None
            self.peer_label.config(text="Select a peer to start chatting")
            self.send_btn.config(state=tk.DISABLED)
            self.file_btn.config(state=tk.DISABLED)
            return
        hostname = selection[0]
        self.selected_peer = hostname
        self.peer_label.config(text=f"Chatting with: {hostname}")
        # Connect if not connected
        if not self.network.is_connected(hostname):
            self.network.connect_to_peer(hostname)
        # Activate buttons after selecting peer
        self.send_btn.config(state=tk.NORMAL)
        self.file_btn.config(state=tk.NORMAL)
        # if selection:
        #     hostname = selection[0]
        #     self.selected_peer = hostname
        #
        #     if hostname in self.network.get_connected_peers():
        #         status = "Connected"
        #     else:
        #         status = "Not connected"
        #         self.connect_to_peer(hostname)
        #
        #     self.peer_label.config(text=f"Chatting with: {hostname} ({status})")

    def connect_to_peer(self, hostname):
        """Connect to another peer using Tailscale"""
        try:
            self.network.connect_to_peer(hostname)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_message(self):
        """Send message to selected peer"""
        message = self.msg_entry.get()
        if not message or not self.selected_peer:
            return

        if self.network.send_message(self.selected_peer, message, msg_type='TEXT_MSG'):
            # Message sent successfully
            self.add_message(f"[Me] {message}")
            self.msg_entry.delete(0, tk.END)
        else:
            # Failed to send
            messagebox.showerror("Error", f"Failed to send message to {self.selected_peer}")

    def send_file(self):
        """Select and send a file to the selected peer"""
        if not self.selected_peer:
            messagebox.showerror("Error", "Select a peer before sending a file.")
            return
        filepath = filedialog.askopenfilename(title="Select file to send")
        if not filepath:
            return
        success = self.network.send_file(self.selected_peer, filepath)
        if success:
            self.add_message(f"[Me] [File sent: {filepath}]")
        else:
            messagebox.showerror("Error", f"Failed to send file to {self.selected_peer}")

    def add_message(self, message):
        """Add a message to the chat display"""

        def _add():
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, message + "\n")
            self.chat_display.see(tk.END)
            self.chat_display.config(state=tk.DISABLED)

        self.root.after(0, _add)


if __name__ == "__main__":
    root = tk.Tk()
    app = StationGUI(root)
    root.mainloop()
