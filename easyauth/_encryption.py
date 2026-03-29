from cryptography.fernet import Fernet

def write_to_log(content):
    with open("log.txt", "a") as f:
        f.write(f"{content}\n")

def generate_key():
    """Generates a secret key and saves it to a file."""
    key = Fernet.generate_key()
    return key.decode()


def encrypt_message(message, key):
    """Encrypts a string message using the key."""
    f = Fernet(key.encode())
    # Convert string to bytes
    encoded_message = message.encode()
    # Encrypt
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message.decode()

def decrypt_message(encrypted_message, key):
    """Decrypts an encrypted byte-string back to a regular string."""
    f = Fernet(key.encode())
    # Decrypt
    decrypted_bytes = f.decrypt(encrypted_message.encode())
    # Convert bytes back to string
    return decrypted_bytes.decode()
