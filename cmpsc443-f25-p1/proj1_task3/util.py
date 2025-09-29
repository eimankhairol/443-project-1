import os
import socket
import struct
import srp
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

BUFFER_SIZE = 4096
PORT = 65436   # Port to listen on (non-privileged ports are > 1023)
SEPARATOR = ","   # A unique separator for sending file info
NONCE_LEN = 12
LEN_PREFIX_FMT = "!I"
SRP_HASH = srp.SHA256
SRP_NG   = srp.NG_2048
SESSION_KEY = None
######### Helper Functions ###########################################
def set_session_key(key: bytes):
    global SESSION_KEY
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("Session key must be 32 bytes")
    SESSION_KEY = key

def _recvall(s: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)

def send_framed(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack(LEN_PREFIX_FMT, len(data)) + data)

def recv_framed(sock: socket.socket) -> bytes:
    (n,) = struct.unpack(LEN_PREFIX_FMT, _recvall(sock, 4))
    return _recvall(sock, n)
###################################################################

# TODO : modify this function, make it secure
# you should be using symmetric key encryption
# you can add parameters if needed
def secure_send_msg(s: socket.socket, msg: bytes) -> None:
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
    if SESSION_KEY is None:
        raise RuntimeError("Session key not set")
    blob = recv_framed(s)
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    aead = ChaCha20Poly1305(SESSION_KEY)
    return aead.decrypt(nonce, ct, None)
