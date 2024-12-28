import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import shutil

class KeyManagement:
    def __init__(self, user_storage_path="user_keys", public_key_storage="public_keys"):
        """
        Initialize the key management module with a specified storage path for private and public keys.
        By default, stores in the same folder as the script.
        """
        # Get the current working directory where the script is being run
        self.base_path = os.getcwd()  # Get current working directory

        # Define storage directories relative to the script's folder
        self.user_storage_path = os.path.join(self.base_path, user_storage_path)  # User keys stored here
        self.public_key_storage = os.path.join(self.base_path, public_key_storage)  # Public keys stored here

        # Create the directories if they don't exist
        os.makedirs(self.user_storage_path, exist_ok=True)
        os.makedirs(self.public_key_storage, exist_ok=True)

    # Symmetric Key Management
    def generate_symmetric_key(self):
        """
        Generate a random 256-bit AES key.
        """
        key = get_random_bytes(32)  # AES-256 key
        return key

    def save_symmetric_key(self, key, user_id, password):
        """
        Securely save the symmetric key to a user-specific file with encryption.
        """
        user_dir = os.path.join(self.user_storage_path, user_id)
        os.makedirs(user_dir, exist_ok=True)  # Ensure user-specific directory exists
        
        # Encrypt the symmetric key with the user's password
        salt = get_random_bytes(16)  # Random salt for PBKDF2
        encrypted_key = self.encrypt_symmetric_key(key, password, salt)

        file_path = os.path.join(user_dir, "symmetric_key.key")
        with open(file_path, "wb") as file:
            file.write(salt)  # Save the salt to the file
            file.write(encrypted_key)  # Save the encrypted symmetric key
        
        # Restrict access to the symmetric key file (only the user can read/write)
        os.chmod(file_path, 0o600)

    def encrypt_symmetric_key(self, symmetric_key, password, salt):
        """
        Encrypt the symmetric key using PBKDF2 and AES.
        """
        key = PBKDF2(password, salt, dkLen=32)  # Derive a key from the password
        cipher = AES.new(key, AES.MODE_GCM)  # AES GCM mode for confidentiality and authenticity
        ciphertext, tag = cipher.encrypt_and_digest(symmetric_key)
        return cipher.nonce + tag + ciphertext  # Save nonce, tag, and ciphertext

    def load_symmetric_key(self, user_id, password):
        """
        Load and decrypt the symmetric key using the user's password.
        """
        user_dir = os.path.join(self.user_storage_path, user_id)
        file_path = os.path.join(user_dir, "symmetric_key.key")
        
        with open(file_path, "rb") as file:
            salt = file.read(16)  # Read the salt from the file
            encrypted_key = file.read()  # Read the encrypted symmetric key
        
        return self.decrypt_symmetric_key(encrypted_key, password, salt)

    def decrypt_symmetric_key(self, encrypted_key, password, salt):
        """
        Decrypt the symmetric key using PBKDF2 and AES.
        """
        key = PBKDF2(password, salt, dkLen=32)  # Derive the decryption key
        nonce, tag, ciphertext = encrypted_key[:16], encrypted_key[16:32], encrypted_key[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    # Asymmetric Key Management
    def generate_rsa_key_pair(self, key_size=2048):
        """
        Generate an RSA public-private key pair.
        """
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def save_private_key(self, private_key, user_id, password):
        """
        Save the private key securely to a user-specific file with encryption.
        """
        user_dir = os.path.join(self.user_storage_path, user_id)
        os.makedirs(user_dir, exist_ok=True)  # Ensure user-specific directory exists
        
        # Encrypt the private key with the user's password
        salt = get_random_bytes(16)  # Random salt for PBKDF2
        encrypted_key = self.encrypt_private_key(private_key, password, salt)

        file_path = os.path.join(user_dir, "private_key.pem")
        with open(file_path, "wb") as file:
            file.write(salt)  # Save the salt to the file
            file.write(encrypted_key)  # Save the encrypted private key
        
        # Restrict access to the private key file (only the user can read/write)
        os.chmod(file_path, 0o600)

    def encrypt_private_key(self, private_key, password, salt):
        """
        Encrypt the private key using PBKDF2 and AES.
        """
        key = PBKDF2(password, salt, dkLen=32)  # Derive a key from the password
        cipher = AES.new(key, AES.MODE_GCM)  # AES GCM mode for confidentiality and authenticity
        ciphertext, tag = cipher.encrypt_and_digest(private_key)
        return cipher.nonce + tag + ciphertext  # Save nonce, tag, and ciphertext

    def load_private_key(self, user_id, password):
        """
        Load and decrypt the private key using the user's password.
        """
        user_dir = os.path.join(self.user_storage_path, user_id)
        file_path = os.path.join(user_dir, "private_key.pem")
        
        with open(file_path, "rb") as file:
            salt = file.read(16)  # Read the salt from the file
            encrypted_key = file.read()  # Read the encrypted private key
        
        return self.decrypt_private_key(encrypted_key, password, salt)

    def decrypt_private_key(self, encrypted_key, password, salt):
        """
        Decrypt the private key using PBKDF2 and AES.
        """
        key = PBKDF2(password, salt, dkLen=32)  # Derive the decryption key
        nonce, tag, ciphertext = encrypted_key[:16], encrypted_key[16:32], encrypted_key[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def save_public_key(self, public_key, user_id):
        """
        Save the public key to the shared public key storage.
        """
        file_path = os.path.join(self.public_key_storage, f"{user_id}_public_key.pem")
        with open(file_path, "wb") as file:
            file.write(public_key)

    def load_public_key(self, user_id):
        """
        Load the public key from the shared public key storage.
        """
        file_path = os.path.join(self.public_key_storage, f"{user_id}_public_key.pem")
        with open(file_path, "rb") as file:
            return file.read()

    # Utility Functions
    def delete_private_key(self, user_id):
        """
        Securely delete the private key and symmetric key for a user.
        """
        user_dir = os.path.join(self.user_storage_path, user_id)
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)  # Delete the user's directory and all its contents
        else:
            raise FileNotFoundError(f"User directory {user_dir} not found.")

    def delete_public_key(self, user_id):
        """
        Securely delete the public key for a user.
        """
        file_path = os.path.join(self.public_key_storage, f"{user_id}_public_key.pem")
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            raise FileNotFoundError(f"Public key file {file_path} not found.")
