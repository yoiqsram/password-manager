from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


def signature(
        key: bytes,
        salt: bytes,
        iter: int = 1000
        ) -> bytes:
    return PBKDF2(key, salt, dkLen=32, count=iter)


def encrypt(
        buffer: bytes,
        key: bytes,
        salt: bytes,
        iter: int = 1000
        ) -> bytes:
    key = signature(key, salt, iter)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(buffer)
    encrypted_buffer = cipher.nonce + tag + ciphertext
    return encrypted_buffer


def decrypt(
        encrypted_buffer: bytes,
        key: bytes,
        salt: bytes,
        iter: int = 1000
        ) -> bytes:
    key = signature(key, salt, iter)    
    nonce = encrypted_buffer[:16]
    tag = encrypted_buffer[16:32]
    ciphertext = encrypted_buffer[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_buffer = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_buffer
