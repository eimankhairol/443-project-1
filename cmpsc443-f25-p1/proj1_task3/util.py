import os
import socket
import struct
import srp
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

BUFFER_SIZE = 4096
PORT = 65436   # Port to listen on (non-privileged ports are > 1023)
SEPARATOR = ","   # A unique separator for sending file info
NONCE_LEN = 12  # Nonce size for ChaCha20-Poly1305 
LEN_PREFIX_FMT = "!I" # Format string for 4-byte big-endian length prefix
SRP_HASH = srp.SHA256  # Hash function used for SRP authentication
SRP_NG   = srp.NG_2048 # SRP group parameters (safe prime, generator)
SESSION_KEY = None
######### Helper Functions ###########################################
def set_session_key(key: bytes):
    """
    Store the shared session key for symmetric encryption
    Must be exactly 32 bytes , ChaCha20-Poly1305 requires 256-bit key
    Raises ValueError if key is not valid
    """
    global SESSION_KEY
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("Session key must be 32 bytes")
    SESSION_KEY = key

def _recvall(s: socket.socket, n: int) -> bytes:
    """
    Receive exactly 'n' bytes from the socket
    Keeps reading until all requested bytes arrive or raises error 
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)

def send_framed(sock: socket.socket, data: bytes):
    """
    Send a message with a 4-byte length prefix
    This ensures the receiver knows exactly how many bytes to read
    """
    sock.sendall(struct.pack(LEN_PREFIX_FMT, len(data)) + data)

def recv_framed(sock: socket.socket) -> bytes:
    """
    Receive a length-prefixed message
    First reads the 4-byte length header, then read the actual payload
    """
    (n,) = struct.unpack(LEN_PREFIX_FMT, _recvall(sock, 4))
    return _recvall(sock, n)
###################################################################

# TODO : modify this function, make it secure
# you should be using symmetric key encryption
# you can add parameters if needed
def secure_send_msg(s: socket.socket, msg: bytes) -> None:
    """
    Encrypt and send a message securely over the socket
    Uses ChaCha20-Poly1305 AEAD with  global SESSION_KEY
    A random 12-byte nonce is generated per message
    Ciphertext = nonce || encrypted_message_with_tag
    """
    if SESSION_KEY is None:
        raise RuntimeError("Session key not set")
    aead = ChaCha20Poly1305(SESSION_KEY)
    nonce = os.urandom(NONCE_LEN)
    ct = aead.encrypt(nonce, msg, None)
    send_framed(s, nonce + ct)

# TODO : modify this function, make is secure,
# you should be using symmetric key encryption
# you can add parameters if needed
# ALSO, consider the size of the msg, it might be larger than 1024 bytes
def secure_receive_msg(s: socket.socket) -> bytes:
    """
    Receive and decrypt a secure message from the socket
    Reads a framed message , nonce + ciphertext
    Splits the first 12 bytes as nonce, remainder as ciphertext+tag
    Uses ChaCha20-Poly1305 decryption with SESSION_KEY
    Returns the plaintext message
    """
    if SESSION_KEY is None:
        raise RuntimeError("Session key not set")
    blob = recv_framed(s)
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    aead = ChaCha20Poly1305(SESSION_KEY)
    return aead.decrypt(nonce, ct, None)
