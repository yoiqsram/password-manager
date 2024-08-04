from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


def encrypt(buffer: bytes, password: bytes, iter: int = 1000) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=iter)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(buffer)
    encrypted_buffer = salt + nonce + tag + ciphertext
    return encrypted_buffer


def decrypt(encrypted_buffer: bytes, password: bytes, iter: int = 1000) -> bytes:
    salt = encrypted_buffer[:16]
    nonce = encrypted_buffer[16:32]
    tag = encrypted_buffer[32:48]
    ciphertext = encrypted_buffer[48:]
    key = PBKDF2(password, salt, dkLen=32, count=iter)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_buffer = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_buffer
