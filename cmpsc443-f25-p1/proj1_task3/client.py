# client.py
# This program will act as the client, connecting to the server for file transfers.

import socket
import os
import sys
import binascii

# --- crypto (Step 1 / Step 3) ---
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

import srp
from util import *

# --- Configuration ---
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65431
DOWNLOAD_FOLDER = "client_folder/downloaded" # Folder to save downloaded files
SEND_FOLDER = "client_folder/filestosend"    # Folder containing files to send
SEPARATOR = "," # A unique separator for sending file info

print("--- Client ---")

# Create the download / send directories if they don't exist
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
os.makedirs(SEND_FOLDER, exist_ok=True)

# ===== Helpers for Step 3 (PBKDF2 + AES-CCM) =====
def derive_file_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file_blob(password: str, plaintext: bytes) -> bytes:
    """
    Encrypt file bytes with AES-CCM using a PBKDF2-derived key.
    Returns payload: [16-byte salt][13-byte nonce][ciphertext+tag]
    """
    salt = os.urandom(16)
    key = derive_file_key(password, salt)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)  # AES-CCM recommended nonce size is 7-13; we choose 13
    ct = aesccm.encrypt(nonce, plaintext, None)
    return salt + nonce + ct

def decrypt_file_blob(password: str, blob: bytes) -> bytes:
    """
    Decrypt payload created by encrypt_file_blob.
    Expects: [16-byte salt][13-byte nonce][ciphertext+tag]
    """
    if len(blob) < 29:
        raise ValueError("Corrupted blob")
    salt, nonce, ct = blob[:16], blob[16:29], blob[29:]
    key = derive_file_key(password, salt)
    aesccm = AESCCM(key)
    return aesccm.decrypt(nonce, ct, None)

# 1. Create a socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        # 2. Connect to the server
        s.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        ''' TODO (Step 1): 
            after connecting, need to derive session keys, and securely exchange them with the server
        '''
        # ---- your code here   ----
        # Receive server public key (framed)
        server_pub_pem = recv_framed(s)
        server_pubkey = serialization.load_pem_public_key(server_pub_pem)

        # Generate 32-byte session key; encrypt to server with RSA-OAEP
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

        # Switch util.py to use the session key
        set_session_key(session_key)

        # DO NOT CHANGE THE PRINT STATEMENT BELOW. PRINT SESSION KEY IF SUCCESSFULLY GENERATED.
        print(f"Generated session key {session_key.hex()}") 
        # ---- your code end here  ----

        # --- ID Validation ---
        '''
            TODO (Step 2):
            Client should never send plaintext passwords. 
            Think about the difference between registering a new ID and logging in with an existing ID.
        '''
        user_id = input("Enter your user ID: ").strip()
        password = input("Enter your password: ").strip()
        #   Filter your id to only allow a combination of of alphanumeric characters [0-9a-zA-Z], and length to be between 2-20 characters.
        #   Filter your password to only allow alphanumeric characters [0-9a-zA-Z], and its length to be between 8 to 64 characters.
        if not (user_id.isalnum() and 2 <= len(user_id) <= 20):
            print("Invalid user ID format. It should be alphanumeric and 2-20 characters long.")
            sys.exit()
        if not (password.isalnum() and 8 <= len(password) <= 64):
            print("Invalid password format. It should be alphanumeric and 8-64 characters long.")
            sys.exit() 

        # ---- your code here   ----
        # SRP: try AUTH first; if unknown user, auto-register
        usr = srp.User(user_id, password)
        _, A = usr.start_authentication()
        secure_send_msg(s, f"AUTH {user_id} {binascii.hexlify(A).decode()}".encode('utf-8'))

        challenge = secure_receive_msg(s).decode('utf-8')
        if challenge.startswith("AUTH_NOUSER"):
            # Register new user
            salt, vkey = srp.create_salted_verification_key(user_id, password)
            salt_hex = binascii.hexlify(salt).decode()
            vkey_hex = binascii.hexlify(vkey).decode()
            secure_send_msg(s, f"REGISTER {user_id}".encode('utf-8'))
            secure_send_msg(s, f"s={salt_hex} v={vkey_hex}".encode('utf-8'))
            response = secure_receive_msg(s).decode('utf-8')
            if response != "REG_OK":
                # DO NOT CHANGE THE PRINT STATEMENT BELOW. ALWAYS INCLUDE IT WHEN ID IS INVALID or REGISTER FAILED.
                print("Authentication Failed.") 
                sys.exit()
            # DO NOT CHANGE THE PRINT STATEMENT BELOW. ALWAYS INCLUDE IT WHEN ID IS VALID or REGISTER SUCCESS.
            print("Authentication Successful.")
        else:
            # Parse s and B
            parts = dict(kv.split("=", 1) for kv in challenge.strip().split())
            s_salt = binascii.unhexlify(parts["s"])
            B = binascii.unhexlify(parts["B"])
            M = usr.process_challenge(s_salt, B)
            if M is None:
                print("Authentication Failed.")
                sys.exit()
            secure_send_msg(s, f"M={binascii.hexlify(M).decode()}".encode('utf-8'))
            proof = secure_receive_msg(s).decode('utf-8')
            if proof.startswith("HAMK="):
                HAMK = binascii.unhexlify(proof.split("=", 1)[1])
                if usr.verify_session(HAMK):
                    # DO NOT CHANGE THE PRINT STATEMENT BELOW. ALWAYS INCLUDE IT WHEN ID IS VALID or REGISTER SUCCESS.
                    print("Authentication Successful.")
                else:
                    print("Authentication Failed.")
                    sys.exit()
            else:
                print("Authentication Failed.")
                sys.exit()
        # ---- your code end here  ----

        print("Commands: send <filepath>, get <filename>, exit")

        ''' TODO (Step 3): before you send files, you need to obtain your master key for file encryption
            You should derive the keys from your password. 
            You should use key derivation function PBKDF2
        '''
        # ---- your code here   ----
        # We derive per-file keys using a random salt per file (see send/get below).
        # Nothing additional required here, as we pack the salt with each blob.
        # file_encryption_key = derive_file_key(password, salt)  # (per-file salt generated later)
        # ---- your code end here  ----

        # --- Command Loop ---
        while True:
            user_input = input(f"{user_id}> ").strip()
            if not user_input:
                continue

            parts = user_input.split()
            command = parts[0]
            
            secure_send_msg(s, user_input.encode('utf-8')) # Send the full command

            if command == "exit":
                break

            elif command == "send":
                if len(parts) < 2:
                    print("Usage: send <filename>")
                    continue
                filename = parts[1]
                filepath = os.path.join(SEND_FOLDER, os.path.basename(filename))
                if not os.path.exists(filepath):
                    print(f"Error: File '{filepath}' not found locally.")
                    print("You need to restart the client to send another command after a failed send.")
                    break

                # Wait for server's green light
                server_response = secure_receive_msg(s).decode('utf-8')
                if server_response == "READY_TO_RECEIVE":
                    ''' TODO (Step 3): 
                        before sending it to the server, you should encrypt the file (Secrecy and Integrity)
                    '''
                    with open(filepath, "rb") as f:
                        file_data = f.read()
                        # ---- your code here   ----
                        encrypted_data = encrypt_file_blob(password, file_data)  # AES-CCM with PBKDF2 key (salt+nonce packed)
                        # ---- your code end here  ----

                        print(f"Server is ready. Sending file '{filepath}'...")
                        # Send the encrypted blob
                        secure_send_msg(s, encrypted_data)
                    
                        # Wait for server's final confirmation
                        confirmation = secure_receive_msg(s).decode('utf-8')
                        print(f"Server: {confirmation}")

            elif command == "get":
                if len(parts) < 2:
                    print("Usage: get <filename>")
                    continue
                filename = parts[1]
                save_path = os.path.join(DOWNLOAD_FOLDER, os.path.basename(filename))
                
                # Check if server has the file
                server_response = secure_receive_msg(s).decode('utf-8')
                if server_response.startswith("ERROR"):
                    print(f"Server: {server_response}")
                elif server_response == "FILE_EXISTS":
                    # Signal server we're ready to receive
                    secure_send_msg(s, "CLIENT_READY".encode('utf-8'))
                    data = secure_receive_msg(s)  # This is the encrypted blob as stored

                    '''TODO (Step 3): decode the file (Secrecy and Integrity)'''
                    # ---- your code here   ----
                    try:
                        decrypted = decrypt_file_blob(password, data)  # derive key via salt in blob, decrypt with AES-CCM
                    except Exception as e:
                        print(f"Decryption failed: {e}")
                        continue
                    # ---- your code end here  ----

                    with open(save_path, "wb") as f:
                        f.write(decrypted)
                    print(f"File '{filename}' downloaded successfully to '{save_path}'")

    except ConnectionRefusedError:
        print("Connection failed. Is the server running?")
    except Exception as e:
        print(f"An error occurred: {e}")

print("Connection closed.")
