# server.py
# This program will act as the server, validating user IDs and handling file transfers.

import socket
import os
import binascii
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import srp

from util import (
    set_session_key,
    secure_send_msg,
    secure_receive_msg,
    send_framed,
    recv_framed,
)

# --- Configuration ---
HOST = '127.0.0.1'   # loopback
PORT = 65431
VALID_IDS_FILE = "server_folder/valid_ids.txt"
SERVER_STORAGE = "server_folder/server_files"
SEPARATOR = ","

# --- Functions for User ID Persistence ---
''' TODO (Step 2):
    The current implementation is flawed because it keeps password as plaintext.
    Use SRP to store the verifier.
'''
def load_valid_ids():
    if not os.path.exists(VALID_IDS_FILE):
        print(f"'{VALID_IDS_FILE}' not found. Creating empty file.")
        open(VALID_IDS_FILE, "w").close()
        return {}
    ids = {}
    with open(VALID_IDS_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(SEPARATOR)
            if len(parts) == 3:
                user, salt_hex, vkey_hex = parts
                ids[user] = (salt_hex, vkey_hex)
    print(f"Loaded {len(ids)} valid IDs from '{VALID_IDS_FILE}'.")
    return ids

''' TODO (Step 2): Modify this function to store verifier (salt + vkey) instead of plaintext passwords.
'''
def save_new_id(user_id, salt_hex, vkey_hex, ids_dict):
    with open(VALID_IDS_FILE, "a") as f:
        f.write(f"{user_id}{SEPARATOR}{salt_hex}{SEPARATOR}{vkey_hex}\n")
    ids_dict[user_id] = (salt_hex, vkey_hex)
    print(f"New user '{user_id}' registered.")

print("--- Server ---")
VALID_IDS = load_valid_ids()
os.makedirs(SERVER_STORAGE, exist_ok=True)

# 1. Create a socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # 2. Bind the socket to the address and port
    s.bind((HOST, PORT))

    # 3. Listen for incoming connections
    s.listen()
    print(f"Server is listening on {HOST}:{PORT}")

    # 4. Accept a connection
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")

        '''
            TODO (Step 1):
            We need to establish a shared symmetric key between the server and client.
            This will be done using public-key cryptography (e.g., RSA).
        '''
        # ---- your code here   ----
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # send server public key (length-prefixed)
        send_framed(conn, pub_pem)

        # receive encrypted session key (length-prefixed)
        enc_session = recv_framed(conn)

        # decrypt session key and switch util.py to use it
        session_key = private_key.decrypt(
            enc_session,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        set_session_key(session_key)

        # DO NOT CHANGE THE PRINT STATEMENT BELOW. PRINT THE SESSION KEY IF SUCCESSFULLY RECEIVED.
        print(f"Decrypted session key: {session_key.hex()}")
        # ---- your code end here  ----

        '''
            TODO (Step 1):
            Now the secret key should be established, and we can use secure_receive_msg and secure_send_msg
            Modify these functions in util.py to make them secure using symmetric key encryption
        '''

        # --- ID & Password Validation ---
        '''
            TODO (Step 2):
            Server should receive the credentials.
            Think how to register new IDs using SRP and how to verify existing IDs.
        '''

        # --- your code here   ----
        # --- SRP phase: expect one of: REGISTER or AUTH ---
        first_line = secure_receive_msg(conn).decode()

        # REGISTER flow: "REGISTER <user_id>"
        if first_line.startswith("REGISTER "):
            user_id = first_line.split(" ", 1)[1].strip()
            # Expect: client sends "s=<hex> v=<hex>"
            reg_payload = secure_receive_msg(conn).decode()
            try:
                parts = dict(kv.split("=", 1) for kv in reg_payload.strip().split())
                salt_hex = parts["s"]
                vkey_hex = parts["v"]
            except Exception:
                secure_send_msg(conn, b"REG_ERROR")
                # do not exit the server; end connection cleanly
                conn.close()
                raise SystemExit

            if user_id in VALID_IDS:
                secure_send_msg(conn, b"REG_EXISTS")
                conn.close()
                raise SystemExit

            save_new_id(user_id, salt_hex, vkey_hex, VALID_IDS)
            secure_send_msg(conn, b"REG_OK")
            authenticated_user = user_id

        # AUTH flow (two-step), with graceful fallback to REGISTER when user unknown
        elif first_line.startswith("AUTH "):
            toks = first_line.split()
            if len(toks) != 3:
                secure_send_msg(conn, b"AUTH_ERROR")
                conn.close()
                raise SystemExit

            user_id, A_hex = toks[1], toks[2]

            # If no such user, tell client and WAIT for REGISTER instead of exiting
            if user_id not in VALID_IDS:
                secure_send_msg(conn, b"AUTH_NOUSER")

                # Expect a REGISTER sequence next
                reg_cmd = secure_receive_msg(conn).decode()
                if not reg_cmd.startswith("REGISTER "):
                    secure_send_msg(conn, b"PROTO_ERROR")
                    conn.close()
                    raise SystemExit
                reg_user = reg_cmd.split(" ", 1)[1].strip()
                reg_payload = secure_receive_msg(conn).decode()
                parts = dict(kv.split("=", 1) for kv in reg_payload.strip().split())
                save_new_id(reg_user, parts["s"], parts["v"], VALID_IDS)
                secure_send_msg(conn, b"REG_OK")
                authenticated_user = reg_user

            else:
                # Normal SRP login
                salt_hex, vkey_hex = VALID_IDS[user_id]
                salt = binascii.unhexlify(salt_hex)
                vkey = binascii.unhexlify(vkey_hex)
                A = binascii.unhexlify(A_hex)

                vrf = srp.Verifier(user_id, salt, vkey, A)
                s_salt, B = vrf.get_challenge()
                if B is None:
                    secure_send_msg(conn, b"AUTH_FAIL")
                    conn.close()
                    raise SystemExit

                challenge = f"s={binascii.hexlify(s_salt).decode()} B={binascii.hexlify(B).decode()}"
                secure_send_msg(conn, challenge.encode())

                # Receive client's proof M
                proof_msg = secure_receive_msg(conn).decode()
                try:
                    M_hex = proof_msg.split("=", 1)[1]
                    M = binascii.unhexlify(M_hex)
                except Exception:
                    secure_send_msg(conn, b"AUTH_ERROR")
                    conn.close()
                    raise SystemExit

                HAMK = vrf.verify(M)
                if HAMK is None:
                    secure_send_msg(conn, b"AUTH_FAIL")
                    conn.close()
                    raise SystemExit

                # Success
                secure_send_msg(conn, f"HAMK={binascii.hexlify(HAMK).decode()}".encode())
                authenticated_user = user_id

        else:
            secure_send_msg(conn, b"PROTO_ERROR")
            conn.close()
            raise SystemExit

        print(f"User '{authenticated_user}' authenticated.")
        user_id = authenticated_user
        # --- your code end here  ----

        # --- Command Handling Loop ---
        while True:
            try:
                command_data = secure_receive_msg(conn).decode('utf-8')
                if not command_data:
                    break  # Client closed the connection

                parts = command_data.split()
                command = parts[0]

                print(f"Received command from '{user_id}': {command_data}")

                '''
                    TODO (Step 3): when server reads the command, it should note is that:
                        First, different users might have files with the same name.
                        You should come up with a strategy to avoid conflicts.

                        Second, while it would be a good idea to make file names secret,
                        we do not consider that for simplicity.

                        Third, you can store the file as a file in a folder. We do are not too concerned about efficiency here.
                        Thus we do not use any database tools.
                '''
                user_dir = os.path.join(SERVER_STORAGE, user_id)
                os.makedirs(user_dir, exist_ok=True)

                if command == "send":
                    filename = parts[1]
                    filepath = os.path.join(user_dir, os.path.basename(filename))

                    # Acknowledge the command and signal readiness to receive file
                    secure_send_msg(conn, "READY_TO_RECEIVE".encode('utf-8'))

                    # Receive file blob (already framed)
                    data = secure_receive_msg(conn)

                    # TODO (Step 3): decrypt file blob here before saving (AES-CCM)
                    with open(filepath, "wb") as f:
                        f.write(data)

                    print(f"File '{filename}' received and saved to '{filepath}'.")
                    secure_send_msg(conn, f"File '{filename}' received.".encode('utf-8'))

                elif command == "get":
                    filename = parts[1]
                    filepath = os.path.join(user_dir, filename)

                    if os.path.exists(filepath):
                        # Signal that file exists and we are sending it
                        secure_send_msg(conn, "FILE_EXISTS".encode('utf-8'))

                        # Wait for client's green light
                        client_ready = secure_receive_msg(conn).decode('utf-8')
                        if client_ready == "CLIENT_READY":
                            with open(filepath, "rb") as f:
                                data = f.read()

                            # TODO (Step 3): encrypt file blob here before sending (AES-CCM)
                            secure_send_msg(conn, data)
                            print(f"File '{filename}' sent to client.")
                    else:
                        secure_send_msg(conn, "ERROR: File not found.".encode('utf-8'))
                        print(f"Client requested non-existent file: '{filename}'")

                elif command == "exit":
                    break

            except (ConnectionResetError, BrokenPipeError):
                print(f"Client {addr} disconnected unexpectedly.")
                break
            except Exception as e:
                print(f"An error occurred: {e}")
                break

print("Connection closed.")
