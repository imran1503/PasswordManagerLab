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

def encrypt_vault(vault, password):
    message = json.dumps(vault).encode()

    salt = os.urandom(16)
    key = derive_key(password, salt)

    aes = AESGCM(key)
    nonce = os.urandom(12)

    encrypted = aes.encrypt(nonce, message, None)

    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "data": encrypted.hex()
    }


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

print("\nEncrypted Data: " + str(encrypted)+ "\n")

vault_data = {
    "salt": salt.hex(),
    "nonce": nonce.hex(),
    "data": encrypted.hex()
}

print("Vault Data: " + str(vault_data) + "\n")

with open("vault.json", "w") as file:
    json.dump(vault_data, file, indent=4)




#Decrypting the message using the same derived key and nonce. 
with open("vault.json", "r") as file:
    saved_vault = json.load(file)

saved_salt = bytes.fromhex(saved_vault["salt"])
saved_nonce = bytes.fromhex(saved_vault["nonce"])
saved_encrypted = bytes.fromhex(saved_vault["data"])

saved_key = derive_key(password, saved_salt)
saved_aes = AESGCM(saved_key)

saved_decrypted = saved_aes.decrypt(
    saved_nonce,
    saved_encrypted,
    None
)
print("Saved Decrypted Data: " + str(saved_decrypted) + "\n") #bytes

saved_vault_data = json.loads(saved_decrypted)
print("Recovered Vault: " + str(saved_vault_data) + "\n") #dictionary