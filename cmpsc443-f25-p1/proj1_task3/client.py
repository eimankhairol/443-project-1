# client.py
# Connects to server, handles login/register, file send/get.

import socket
import os
import sys
import binascii
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import srp

from util import (
    set_session_key,
    secure_send_msg,
    secure_receive_msg,
    send_framed,
    recv_framed,
)

# --- Config ---
HOST = '127.0.0.1'
PORT = 65431
DOWNLOAD_FOLDER = "client_folder/downloaded"
SEND_FOLDER = "client_folder/filestosend"
SEPARATOR = ","

print("--- Client ---")
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
os.makedirs(SEND_FOLDER, exist_ok=True)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        # --- Step 1: RSA handshake ---
        server_pub_pem = recv_framed(s)
        server_pubkey = serialization.load_pem_public_key(server_pub_pem)

        # Generate a random 32-byte session key and send encrypted to server
        session_key = os.urandom(32)
        enc_session = server_pubkey.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        send_framed(s, enc_session)

        # Set global key for util.py
        set_session_key(session_key)

        # DO NOT CHANGE: must print generated session key
        print(f"Generated session key {session_key.hex()}")

        # --- Step 2: SRP ---
        user_id = input("Enter your user ID: ").strip()
        password = input("Enter your password: ").strip()

        # Try AUTH first
        usr = srp.User(user_id, password)
        _, A = usr.start_authentication()
        secure_send_msg(s, f"AUTH {user_id} {binascii.hexlify(A).decode()}".encode())

        challenge = secure_receive_msg(s).decode()
        if challenge.startswith("AUTH_NOUSER"):
            # Register new user (server will stay open waiting for this)
            salt, vkey = srp.create_salted_verification_key(user_id, password)
            salt_hex = binascii.hexlify(salt).decode()
            vkey_hex = binascii.hexlify(vkey).decode()
            secure_send_msg(s, f"REGISTER {user_id}".encode())
            secure_send_msg(s, f"s={salt_hex} v={vkey_hex}".encode())
            response = secure_receive_msg(s).decode()
            if response == "REG_OK":
                print("Registration successful.")
            else:
                print("Authentication Failed.")
                sys.exit()
        else:
            # Handle SRP login
            parts = dict(kv.split("=", 1) for kv in challenge.strip().split())
            salt = binascii.unhexlify(parts["s"])
            B = binascii.unhexlify(parts["B"])

            M = usr.process_challenge(salt, B)
            if M is None:
                print("Authentication Failed.")
                sys.exit()

            secure_send_msg(s, f"M={binascii.hexlify(M).decode()}".encode())

            proof = secure_receive_msg(s).decode()
            if proof.startswith("HAMK="):
                HAMK = binascii.unhexlify(proof.split("=", 1)[1])
                if usr.verify_session(HAMK):
                    print("Authentication Successful.")
                else:
                    print("Authentication Failed.")
                    sys.exit()
            else:
                print("Authentication Failed.")
                sys.exit()

        # --- Step 3: Command loop ---
        print("Commands: send <file>, get <file>, exit")
        while True:
            user_input = input(f"{user_id}> ").strip()
            if not user_input:
                continue

            parts = user_input.split()
            command = parts[0]

            # Send the full command
            secure_send_msg(s, user_input.encode())

            if command == "exit":
                break

            elif command == "send":
                if len(parts) < 2:
                    print("Usage: send <filename>")
                    continue
                filename = parts[1]
                filepath = os.path.join(SEND_FOLDER, os.path.basename(filename))
                if not os.path.exists(filepath):
                    print(f"File '{filepath}' not found.")
                    break

                # Wait for server's green light
                resp = secure_receive_msg(s).decode()
                if resp == "READY_TO_RECEIVE":
                    with open(filepath, "rb") as f:
                        file_data = f.read()

                    ''' TODO (Step 3):
                        before sending it to the server, you should encrypt the file (Secrecy and Integrity)
                    '''
                    # ---- your code here   ----
                    encrypted_data = file_data  # placeholder for AES-CCM encrypted data

                    secure_send_msg(s, encrypted_data)
                    conf = secure_receive_msg(s).decode()
                    print(f"Server: {conf}")

            elif command == "get":
                if len(parts) < 2:
                    print("Usage: get <filename>")
                    continue
                filename = parts[1]
                save_path = os.path.join(DOWNLOAD_FOLDER, os.path.basename(filename))

                # Check if server has the file
                resp = secure_receive_msg(s).decode()
                if resp.startswith("ERROR"):
                    print(f"Server: {resp}")
                elif resp == "FILE_EXISTS":
                    # Signal server we're ready to receive
                    secure_send_msg(s, b"CLIENT_READY")

                    data = secure_receive_msg(s)
                    ''' TODO (Step 3): decode the file (Secrecy and Integrity) '''
                    # ---- your code here   ----
                    decrypted = data  # placeholder for AES-CCM decrypted data

                    with open(save_path, "wb") as f:
                        f.write(decrypted)
                    print(f"File saved to '{save_path}'")

    except Exception as e:
        print(f"Error: {e}")

print("Connection closed.")
