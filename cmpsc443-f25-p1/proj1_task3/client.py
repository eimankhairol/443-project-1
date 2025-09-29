# client.py
# This program will act as the client, connecting to the server for file transfers.

import socket
import os
import sys
import binascii
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import srp
from util import *
from util import (
    set_session_key,
    secure_send_msg,
    secure_receive_msg,
    send_framed,
    recv_framed,
    PORT,
    SEPARATOR
)



# --- Configuration ---
HOST = '127.0.0.1'  # The server's hostname or IP address
DOWNLOAD_FOLDER = "client_folder/downloaded" # Folder to save downloaded files
SEND_FOLDER = "client_folder/filestosend"    # Folder containing files to send
SRP_HASH = srp.SHA256 # Hash algo for SRP
SRP_NG   = srp.NG_2048  # Group paremeters for SRP

print("--- Client ---")

# Create the download directory if it doesn't exist
if not os.path.exists(DOWNLOAD_FOLDER):
    os.makedirs(DOWNLOAD_FOLDER)
    print(f"Created directory: {DOWNLOAD_FOLDER}")

# Create the send directory if it doesn't exist
if not os.path.exists(SEND_FOLDER):
    os.makedirs(SEND_FOLDER)
    print(f"Created directory: {SEND_FOLDER}")

# ===== Helper Functions =====
def derive_file_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from password+salt using PBKDF2-HMAC-SHA256.
    This ensures a unique key per file since salt is random per file.
    """
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
    Encrypt a file with AES-CCM using a key derived from password+salt.
    Blob format: salt(16) || nonce(13) || ciphertext+tag
    """
    salt = os.urandom(16)
    key = derive_file_key(password, salt)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)  # AES-CCM recommended nonce size is 7-13; we choose 13
    ct = aesccm.encrypt(nonce, plaintext, None)
    return salt + nonce + ct

def decrypt_file_blob(password: str, blob: bytes) -> bytes:
    """
    Decrypt a previously encrypted file blob.
    Splits into salt, nonce, ciphertext+tag, then recomputes the key and decrypts.
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
        # Establishing secure channel
        # Receive server public key, RSA
        server_pub_pem = recv_framed(s)
        server_pubkey = serialization.load_pem_public_key(server_pub_pem)

        # Generate session key and encrypt with server's RSA public key
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
        # User AUth for SRP
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
        # Start SRP authentication
        usr = srp.User(user_id, password, hash_alg=SRP_HASH, ng_type=SRP_NG)
        _, A = usr.start_authentication()
        secure_send_msg(s, f"AUTH {user_id} {binascii.hexlify(A).decode()}".encode('utf-8'))

        challenge = secure_receive_msg(s).decode('utf-8')
        
        if challenge.startswith("AUTH_NOUSER"):
            # New user registration
            salt, vkey = srp.create_salted_verification_key(user_id, password, hash_alg=SRP_HASH, ng_type=SRP_NG)
            salt_hex = binascii.hexlify(salt).decode()
            vkey_hex = binascii.hexlify(vkey).decode()
            secure_send_msg(s, f"REGISTER {user_id}".encode('utf-8'))
            secure_send_msg(s, f"s={salt_hex} v={vkey_hex}".encode('utf-8'))
            response = secure_receive_msg(s).decode('utf-8')
            if response != "REG_OK":
                print("Authentication Failed.")  
                sys.exit()
            print("Authentication Successful.")  
        else:
            # Existing user login flow
            parts = dict(kv.split("=", 1) for kv in challenge.strip().split())
            s_hex = parts["s"].strip()    
            B_hex = parts["B"].strip()
            s_salt = binascii.unhexlify(s_hex)
            B      = binascii.unhexlify(B_hex)
            
            # Process challeenge to compute client proof
            M = usr.process_challenge(s_salt, B)
            if M is None:
                print("Authentication Failed.")
                sys.exit()

            secure_send_msg(s, f"M={binascii.hexlify(M).decode()}".encode('utf-8'))

            # Verify server proof
            proof = secure_receive_msg(s).decode('utf-8')
            if proof.startswith("HAMK="):
                hamk_hex = proof.split("=", 1)[1].strip()
                HAMK = binascii.unhexlify(hamk_hex)
                usr.verify_session(HAMK)   # updates state

                if usr.authenticated():
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
        # --- Command Loop ---
        # File transfer
    
        while True:
            user_input = input(f"{user_id}> ")
            if not user_input:
                continue

            parts = user_input.split()
            command = parts[0]
            
            secure_send_msg(s, user_input.encode('utf-8')) # Send the full command

            if command == "exit":
                break

            elif command == "send":
                # Send file to server, is encrypted on client side
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
                # Download a file from server, decrypt on client side)
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
                        decrypted = decrypt_file_blob(password, data)  # Derive key via salt in blob, decrypt with AES-CCM
                    except Exception as e:
                        print(f"Decryption failed: {e}")
                        continue

                    with open(save_path, "wb") as f:
                        f.write(decrypted)
                    print(f"File '{filename}' downloaded successfully to '{save_path}'")

    except ConnectionRefusedError:
        print("Connection failed. Is the server running?")
    except Exception as e:
        print(f"An error occurred: {e}")

print("Connection closed.")
