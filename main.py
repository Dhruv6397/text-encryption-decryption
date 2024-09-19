from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
import os


# Function to generate a key from a password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key


# Encrypt the text
def encrypt_text(plain_text, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()

    return b64encode(salt + iv + encrypted_text).decode('utf-8')


# Decrypt the text
def decrypt_text(encrypted_text, password):
    encrypted_data = b64decode(encrypted_text)

    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_message = encrypted_data[32:]

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return decrypted_message.decode('utf-8')


if __name__ == "__main__":

    text = "I am dhruv"
    password = "Zxcv@0987"

    encrypted = encrypt_text(text, password)
    print(f"Encrypted Text: {encrypted}")

    decrypted = decrypt_text(encrypted, password)
    print(f"Decrypted Text: {decrypted}")
