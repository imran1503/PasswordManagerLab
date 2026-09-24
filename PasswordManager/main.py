from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json

UIpassword = input("Enter vault password: ")

vault = {
    "github": {
        "username": "test@example.com",
        "password": "FakeGitHubPassword123!",
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


def decrypt_vault(vault_data, password):
    salt = bytes.fromhex(vault_data["salt"])
    nonce = bytes.fromhex(vault_data["nonce"])
    encrypted = bytes.fromhex(vault_data["data"])

    key = derive_key(password, salt)

    aes = AESGCM(key)

    decrypted = aes.decrypt(nonce, encrypted, None)

    return json.loads(decrypted)


password = UIpassword

vault_data = encrypt_vault(vault, password)

with open("vault.json", "w") as file:
    json.dump(vault_data, file, indent=4)


with open("vault.json", "r") as file:
    saved_vault = json.load(file)

recovered_vault = decrypt_vault(saved_vault, password)

print("Recovered Vault: " + str(recovered_vault) + "\n")
print("Vault matches original: " + str(recovered_vault == vault))

