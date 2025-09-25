# server.py
# This program will act as the server, validating user IDs and handling file transfers.

import socket
import os

# --- Configuration ---
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
# DEFAULT_IDS = {"user1", "user2", "admin"} # Default IDs if no file exists
VALID_IDS_FILE = "server_folder/valid_ids.txt" # File to store valid user IDs
SERVER_STORAGE = "server_folder/server_files" # Directory to store files received from clients

from util import *

# --- Functions for User ID Persistence ---
''' TODO (Step 2): 
    The current implementation is flawed because it keeps password as plaintext.
    Use SRP to store the verifier. 
'''
def load_valid_ids():
    # load valid IDs from a file. If the file doesn't exist, creates it empty
    if not os.path.exists(VALID_IDS_FILE):
        print(f"'{VALID_IDS_FILE}' not found. Creating an empty file.")
        with open(VALID_IDS_FILE, "w") as f:
            pass  # Just create an empty file
        return set()
    
    ids = {}
    with open(VALID_IDS_FILE, "r") as f:
        for line in f:
            if SEPARATOR in line:
                user, pwd = line.strip().split(SEPARATOR, 1)
                ids[user] = pwd
    
    print(f"Loaded {len(ids)} valid IDs from '{VALID_IDS_FILE}'.")
    return ids

''' TODO (Step 2): Modify this function to store verifier (salt + vkey) instead of plaintext passwords.
'''
def save_new_id(user_id, password, ids_dict):
    """Appends a new user ID to the file and updates the set."""
    if user_id and password:
        # --- your code here   ---- 
        with open(VALID_IDS_FILE, "a") as f:
            f.write(f"{user_id}{SEPARATOR}{password}\n") # placeholder for storing password securely 

        ids_dict[user_id] = password # placeholder for storing password securely

        print(f"New user '{user_id}' registered.") 


print("--- Server ---")

# Load valid IDs from the file at startup
VALID_IDS = load_valid_ids()

# Create the server storage directory if it doesn't exist
if not os.path.exists(SERVER_STORAGE):
    os.makedirs(SERVER_STORAGE)
    print(f"Created directory: {SERVER_STORAGE}")

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
            
            Steps:
            1. Server generates a public/private key pair.
            2. User gets the public key for server. (We assume this is done in advance)
            3. Client generates a symmetric key (e.g., for AES) and encrypts it with the server's public key.
            4. Client sends the encrypted symmetric key to the server.
            5. Server decrypts the symmetric key using its private key.
            6. Both server and client now use this symmetric key for encrypting/decrypting further communication.
        '''
        # ---- your code here   ----
        session_key = conn.recv(1024) # placeholder for receiving keys from client


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
        credentials = secure_receive_msg(conn).decode('utf-8') # placeholder for receiving credentials


        # placehoder logic for validating credentials
        if SEPARATOR in credentials:
            user_id, password = credentials.split(SEPARATOR, 1)
        else:
            print("Invalid credentials format received.")
            conn.close()
            exit()

        if user_id in VALID_IDS:
            if VALID_IDS[user_id] == password: # placeholder for secure password check 
                secure_send_msg(conn, "ID_VALID".encode('utf-8'))
            else:
                secure_send_msg(conn, "ID_INVALID".encode('utf-8'))
                print(f"Invalid password for user '{user_id}'.")
                conn.close()
                exit()
        else:
            # Register new user
            save_new_id(user_id, password, VALID_IDS)
            secure_send_msg(conn, "ID_VALID".encode('utf-8'))

        # --- your code end here  ----

        print(f"User '{user_id}' authenticated.") 


        # --- Command Handling Loop ---
        while True:
            try:
                command_data = secure_receive_msg(conn).decode('utf-8')
                if not command_data:
                    break # Client closed the connection
                    
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
                if command == "send":
                    filename = parts[1]
                    filepath = os.path.join(SERVER_STORAGE, os.path.basename(filename))

                    # Acknowledge the command and signal readiness to receive file
                    secure_send_msg(conn, "READY_TO_RECEIVE".encode('utf-8'))

                    # Receive file size first (16 bytes)
                    data = secure_receive_msg(conn)
                    print(f"receiving data {data}")
                    with open(filepath, "wb") as f:
                        f.write(data)
                    print(f"File '{filename}' received and saved to '{filepath}'.")

                    secure_send_msg(conn, f"File '{filename}' received successfully.".encode('utf-8'))

                elif command == "get":
                    filename = parts[1]
                    filepath = os.path.join(SERVER_STORAGE, filename)

                    if os.path.exists(filepath):
                        # Signal that file exists and we are sending it
                        secure_send_msg(conn, "FILE_EXISTS".encode('utf-8'))
                        
                        # Wait for client's green light to avoid race conditions
                        client_ready = secure_receive_msg(conn).decode('utf-8')
                        if client_ready == "CLIENT_READY":
                            # read the file data
                            with open(filepath, "rb") as f:
                                data = f.read()
                                # Send the file
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

