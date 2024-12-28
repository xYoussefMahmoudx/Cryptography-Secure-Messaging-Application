import socket
import threading
import sys
import hashlib
from db import DB
import json
import base64
import key_management as KMM
import block_cypher as BC
import RSA as RS
import hashing as HS


# Database instance
db = DB()
current_peer_username = None
current_username=""
current_password=""


def handle_incoming_messages(connection, connection_list):
    global current_username
    global current_password

    """Listen for incoming messages."""
    global current_peer_username
    try:
        if current_peer_username is None:
            peer_username = connection.recv(1024).decode('utf-8')
            current_peer_username = peer_username
        
    

        while True:
            message = connection.recv(1024).decode('utf-8')
            if message:
                try:
                    
                # structured_message = {
                #     "cipher_text":cp['ciphertext'],
                #     'nonce':cp['nonce'],
                #     'tag':cp['tag'],
                #     'encrypted_sym_key':encrypted_sym_key,
                #     'hashed_message':hashed_message

                # }
                    message_data = json.loads(message)  # Deserialize JSON
                    cipher_text = message_data.get("cipher_text", "Unknown")
                    nonce = message_data.get("nonce", "")
                    tag = message_data.get("tag", "")
                    encrypted_sym_key = base64.b64decode(message_data.get("encrypted_sym_key", ""))
                    hashed_message = message_data.get("hashed_message", "")
                    km=KMM.KeyManagement()
                    private_key=km.load_private_key(user_id=current_username,password=current_password)
                
                    decrypted_sym_key=RS.decrypt(private_key=private_key,ciphertext=encrypted_sym_key)
                
                    bc=BC.AESEncryption(decrypted_sym_key)
                    plain_message=bc.decrypt(ciphertext=cipher_text,nonce=nonce,tag=tag)
                    hashing_validate=HS.HashingModule.verify_hash(data=plain_message,provided_hash=hashed_message)
                
                    if(hashing_validate):

                        print(f"\n{current_peer_username}: {plain_message} ")
                    else:
                        print(f"Communication between you and {current_peer_username} is insecure ")
                        connection_list.remove(connection)
                        connection.close()
                        current_peer_username = None
                        print("\n connection closed forcebly to maintain security")
                    

                except json.JSONDecodeError:
                    print(f"\nInvalid message format received: {message}")
            else:
                raise ConnectionError("Peer disconnected.")
    except Exception as e:
        print(f"\nConnection to peer lost: {e}")
        connection_list.remove(connection)
        connection.close()
        current_peer_username = None
        print("\nReturning to the connected user menu...")


def start_server(server_port, connection_list):
    """Start a thread to act as a server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', server_port))
    server_socket.listen(5)
    print(f"Server started on port {server_port}, waiting for connections...")
    while True:
        connection, address = server_socket.accept()
        print(f"Connected to {address}")
        connection_list.append(connection)
        connection.send(username.encode('utf-8'))
        threading.Thread(
            target=handle_incoming_messages, args=(connection, connection_list), daemon=True
        ).start()


def connect_to_peer(peer_host, peer_port, connection_list):
    global current_peer_username
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((peer_host, peer_port))
        print(f"Connected to peer on port {peer_port}!")
        connection_list.append(client_socket)

        # Send the username only once when the connection is established
        client_socket.send(username.encode('utf-8'))
        peer_username = client_socket.recv(1024).decode('utf-8')
        current_peer_username = peer_username
        print(f"\nConnected with peer username: {current_peer_username}")

        threading.Thread(
            target=handle_incoming_messages, args=(client_socket, connection_list), daemon=True
        ).start()
    except Exception as e:
        print(f"Failed to connect to peer on port {peer_port}: {e}")


def get_online_users(username):
    """Fetch online users excluding the current user."""
    online_users = db.db.online_peers.find({"username": {"$ne": username}})
    return [(user["username"], user["ip"], user["port"]) for user in online_users]


def signup():
    """Register a new user."""
    print("\nSignup:")
    username = input("Enter a username: ")
    if db.is_account_exist(username):
        print("Username already exists. Try logging in.")
        return None, None

    password = input("Enter a password: ")
    db.register(username, password)
    km=KMM.KeyManagement()
    privatekey,publickey=km.generate_rsa_key_pair()
    km.save_private_key(private_key=privatekey,user_id=username,password=password)
    km.save_public_key(public_key=publickey,user_id=username)

    print("Signup successful. Please log in.")
    return None, None


def login():
    global current_username
    global current_password
    """Log in an existing user."""
    print("\nLogin:")
    username = input("Enter your username: ")
    if not db.is_account_exist(username):
        print("Account does not exist. Please sign up.")
        return None, None

    password = input("Enter your password: ")
    if db.get_password(username) != hashlib.sha256(password.encode('utf-8')).hexdigest():
        print("Invalid password.")
        return None, None
    current_username=username
    current_password=password

    

    print("Login successful.")
    return username, password


def start_peer(server_port, username):
    """Initialize the peer."""
    global current_peer_username
    # Mark the user as online
    db.user_login(username, 'localhost', server_port)
    print(f"Logged in as {username}")

    connection_list = []

    # Start the server thread
    threading.Thread(target=start_server, args=(server_port, connection_list), daemon=True).start()

    while True:
        print("\nFetching online users...")
        online_users = get_online_users(username)
        if not online_users:
            print("No users are online.")
        else:
            print("Online users:")
            for idx, user in enumerate(online_users, start=1):
                print(f"{idx}. {user[0]} (IP: {user[1]}, Port: {user[2]})")
            print("0. Refresh list")

        try:
            choice = int(input("Select a user to connect to (or 0 to refresh): "))
            if choice == 0:
                continue  # Refresh the online users list
            selected_user = online_users[choice - 1]
            peer_host, peer_port = selected_user[1], int(selected_user[2])
            connect_to_peer(peer_host, peer_port, connection_list)
        except (ValueError, IndexError):
            print("Invalid selection. Try again.")

        # Sending messages
        while connection_list:
            message = input("You: ")
            if message.lower() == '!logout':
                break
            try:
                """ message = plaintext
                create symmetic key by key management module then encrypt message
                encrypt symmetric key by rsa public key
                hashed plain text 
                nonce - tag


                """
                km=KMM.KeyManagement()
                sym_key=km.generate_symmetric_key()
                            
                bc=BC.AESEncryption(sym_key)
                cp=bc.encrypt(message)
                
                public_key=km.load_public_key(current_peer_username)
                

                encrypted_sym_key=RS.encrypt(public_key=public_key,plaintext=sym_key)
                hashed_message=HS.HashingModule.generate_hash(message)





                structured_message = {
                    "cipher_text":cp['ciphertext'],
                    'nonce':cp['nonce'],
                    'tag':cp['tag'],
                    'encrypted_sym_key':base64.b64encode(encrypted_sym_key).decode('utf-8'),
                    'hashed_message':hashed_message


                }

                message_json = json.dumps(structured_message)  # Serialize to JSON
                for conn in connection_list:
                    conn.send(message_json.encode('utf-8'))


            except Exception as e:
                print(f"Error sending message: {e}")

        # If no connections left, break to main menu
        if not connection_list:
            print("\nNo active connections. Returning to the user menu...")

        # Mark the user as offline
        db.user_logout(username)
        print(f"Logged out {username}.")
        break


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python peer.py <server_port>")
        sys.exit(1)

    server_port = int(sys.argv[1])

    username = None
    password = None

    # Authentication menu
    while not username:
        print("\nWelcome to the P2P Secure Chat!")
        print("1. Signup")
        print("2. Login")
        choice = input("Choose an option: ")

        if choice == '1':
            username, password = signup()
        elif choice == '2':
            username, password = login()
        else:
            print("Invalid choice. Please select 1 or 2.")

    start_peer(server_port, username)
