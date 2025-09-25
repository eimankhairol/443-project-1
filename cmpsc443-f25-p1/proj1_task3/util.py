import os    
import socket

BUFFER_SIZE = 4096
PORT = 65431     # Port to listen on (non-privileged ports are > 1023)
SEPARATOR = "," # A unique separator for sending file info



# TODO : modify this function, make it secure
# you should be using symmetric key encryption
# you can add parameters if needed
def secure_send_msg(s : socket, msg: bytes):
    # Placeholder for secure sending, e.g., encryption can be added here
    # ---- your code here   ---- 
    s.sendall(msg)

# TODO : modify this function, make is secure, 
# you should be using symmetric key encryption
# you can add parameters if needed
# ALSO, consider the size of the msg, it might be larger than 1024 bytes
def secure_receive_msg(s: socket) -> bytes:
    # Placeholder for secure sending, e.g., encryption can be added here
    # ---- your code here   ---- 
    return s.recv(1024)

