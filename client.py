import socket
import threading
import rsa
import tkinter as tk
from tkinter import scrolledtext, Entry, messagebox

def connect_to_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    public_key, private_key = rsa.newkeys(1024)

    server_address = ("127.0.0.1", 9999)
    try:
        client.connect(server_address)

        # Receive public key from the server
        server_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))

        # Send client public key to the server
        client.send(public_key.save_pkcs1("PEM"))
    except Exception as e:
        messagebox.showerror("Error", f"Error connecting to the server: {e}")
        client.close()
        return None, None, None

    return client, public_key, private_key, server_public_key

def send_message(client, message_entry, server_public_key, chat_display):
    message = message_entry.get()
    if message:
        # Display own message in the chat display
        chat_display.insert(tk.END, f"You: {message}\n")
        chat_display.yview(tk.END)

        # Encrypt the message with the server's public key
        encrypted_message = rsa.encrypt(message.encode(), server_public_key)

        # Send the encrypted message to the server
        client.send(encrypted_message)

        # Clear the message entry
        message_entry.delete(0, tk.END)

def receive_messages(client, private_key, chat_display):
    try:
        while True:
            # Receive encrypted message from the server
            encrypted_message = client.recv(1024)
            if not encrypted_message:
                break

            # Decrypt the message with the client's private key
            decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()

            # Display the message in the chat display with sender information
            chat_display.insert(tk.END, decrypted_message + "\n")
            chat_display.yview(tk.END)
    except:
        pass

def on_closing(client, root):
    client.close()
    root.destroy()

def main():
    client, public_key, private_key, server_public_key = connect_to_server()

    if not client:
        return

    root = tk.Tk()
    root.title("Secure Chat App")

    chat_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=10)
    chat_display.pack(padx=10, pady=10)

    message_entry = Entry(root, width=40)
    message_entry.pack(padx=10, pady=5)

    send_button = tk.Button(root, text="Send", command=lambda: send_message(client, message_entry, server_public_key, chat_display))
    send_button.pack(pady=5)

    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(client, root))

    # Start a separate thread for receiving messages
    threading.Thread(target=lambda: receive_messages(client, private_key, chat_display), daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    main()
