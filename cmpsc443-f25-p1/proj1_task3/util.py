import os
import socket
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_LEN = 12
LEN_PREFIX_FMT = "!I"

# Global session key (set after RSA handshake)
SESSION_KEY = None

def set_session_key(key: bytes):
    """
    Call this after key exchange to set the session key (32 bytes).
    """
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
    """
    Send data with a 4-byte big-endian length prefix.
    """
    sock.sendall(struct.pack(LEN_PREFIX_FMT, len(data)) + data)

def recv_framed(sock: socket.socket) -> bytes:
    """
    Receive a length-prefixed frame.
    """
    (n,) = struct.unpack(LEN_PREFIX_FMT, _recvall(sock, 4))
    return _recvall(sock, n)

# TODO : modify this function, make it secure
# you should be using symmetric key encryption
# you can add parameters if needed
def secure_send_msg(s: socket.socket, msg: bytes) -> None:
    """
    Encrypt and send msg using ChaCha20-Poly1305.
    Wire format: [4-byte length][12-byte nonce][ciphertext+tag]
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
    Receive and decrypt a message sent with secure_send_msg.
    """
    if SESSION_KEY is None:
        raise RuntimeError("Session key not set")
    blob = recv_framed(s)
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    aead = ChaCha20Poly1305(SESSION_KEY)
    return aead.decrypt(nonce, ct, None)
