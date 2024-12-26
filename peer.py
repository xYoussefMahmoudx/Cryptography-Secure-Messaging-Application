import socket
import threading
import sys

def handle_incoming_messages(connection):
    """Listen for incoming messages."""
    while True:
        try:
            message = connection.recv(1024).decode('utf-8')
            if message:
                print(f"\nPeer: {message}")
            else:
                break
        except:
            print("Connection lost.")
            break

def start_server(server_port, connection_list):
    """Start a thread to act as a server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', server_port))
    server_socket.listen(1)
    print(f"Server started on port {server_port}, waiting for a connection...")
    connection, address = server_socket.accept()
    print(f"Connected to {address}")
    connection_list.append(connection)
    threading.Thread(target=handle_incoming_messages, args=(connection,)).start()

def connect_to_peer(peer_host, peer_port, connection_list):
    """Connect to a peer."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            client_socket.connect((peer_host, peer_port))
            print(f"Connected to peer on port {peer_port}!")
            connection_list.append(client_socket)
            threading.Thread(target=handle_incoming_messages, args=(client_socket,)).start()
            break
        except:
            print(f"Retrying connection to peer on port {peer_port}...")
            threading.Event().wait(2)  # Retry after 2 seconds

def start_peer(server_port, peer_host, peer_port):
    """Initialize the peer."""
    connection_list = []

    # Start the server thread
    threading.Thread(target=start_server, args=(server_port, connection_list)).start()

    # Connect to another peer
    threading.Thread(target=connect_to_peer, args=(peer_host, peer_port, connection_list)).start()

    # Allow sending messages
    while True:
        if connection_list:
            message = input("You: ")
            if message.lower() == 'exit':
                break
            connection_list[0].send(message.encode('utf-8'))

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python peer.py <server_port> <peer_host> <peer_port>")
        sys.exit(1)

    server_port = int(sys.argv[1])
    peer_host = sys.argv[2]
    peer_port = int(sys.argv[3])

    start_peer(server_port, peer_host, peer_port)
