import socket
import threading
import rsa

def initialize_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 9999))
    server.listen()
    return server

def handle_client(client, clients, public_keys):
    public_key, private_key = rsa.newkeys(1024)

    client.send(public_key.save_pkcs1("PEM"))     # Send public key to the client
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))   # Receive public key from the client

    clients.append(client)
    public_keys.append(public_partner) 

    try:
        while True:
            encrypted_message = client.recv(1024)    # Receive encrypted message from the client
            if not encrypted_message:
                break
  
            decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()# Decrypt and broadcast the message to all clients
            print(f"Client {clients.index(client)}: {decrypted_message}")

            for other_client in clients:
                if other_client != client:
                    other_client.send(rsa.encrypt(f"Client {clients.index(client)}: {decrypted_message}".encode(), public_keys[clients.index(other_client)]))      # Encrypt and send the message to other clients
    except: 
        pass
    finally:
        index = clients.index(client)    # Remove the client and its public key upon disconnection
        clients.remove(client)
        public_keys.pop(index)
        client.close()

def main():
    server = initialize_server()
    print("Waiting for connections...")

    clients = []
    public_keys = []

    try:
        while True:
            client, addr = server.accept()
            print(f"New connection from {addr}")
            threading.Thread(target=handle_client, args=(client, clients, public_keys)).start()
    except KeyboardInterrupt:
        print("Server shutting down.")
        server.close()

if __name__ == "__main__":
    main()

