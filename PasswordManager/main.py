from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json

vault = {
    "github": {
        "username": "test@example.com",
        "password": "FakePassword123!",
        "url": "https://github.com"
    }
}
def derive_key(password, salt):
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )

#Encypting a message and password using AES-GCM with a derived key from Argon2
message = json.dumps(vault).encode()
password = "test-password"
salt = os.urandom(16)

key = derive_key(password, salt)

aes = AESGCM(key)

# Generate a unique 12-byte nonce for this AES-GCM encryption. The nonce ensures that encrypting the same plaintext with the same key doesn't produce the same ciphertext every time.
nonce = os.urandom(12)


# Encrypt the vault data

encrypted = aes.encrypt(nonce, message, None)

print(encrypted)

#Decrypting the message using the same derived key and nonce. 

decrypted = aes.decrypt(nonce, encrypted, None)

print(decrypted)