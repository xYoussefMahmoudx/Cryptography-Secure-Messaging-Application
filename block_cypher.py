from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class AESEncryption:
    def __init__(self, key):
        """
        Initialize with a user-provided AES key and validate its length.
        :param key: The symmetric key provided by the user.
        """
        if len(key) not in (16, 24, 32):
            raise ValueError("Invalid key length. Key must be 16, 24, or 32 bytes long.")
        self.key = key

    def encrypt(self, plaintext: str) -> dict:
        """
        Encrypts the given plaintext using AES in EAX mode.
        :param plaintext: The plaintext message to encrypt.
        :return: A dictionary containing the ciphertext, tag, and nonce (all base64 encoded).
        """
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode(),
            "nonce": base64.b64encode(cipher.nonce).decode()
        }

    def decrypt(self, ciphertext: str, tag: str, nonce: str) -> str:
        # Decode the base64 inputs
        ciphertext = base64.b64decode(ciphertext)
        tag = base64.b64decode(tag)
        nonce = base64.b64decode(nonce)

        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()

# Example Usage
if __name__ == "__main__":
    aes = AESEncryption()

    # Encrypt a message
    message = "This is a secure message."
    encrypted_data = aes.encrypt(message)
    print("Encrypted Data:", encrypted_data)

    # Decrypt the message
    decrypted_message = aes.decrypt(
        encrypted_data["ciphertext"],
        encrypted_data["tag"],
        encrypted_data["nonce"]
    )
    print("Decrypted Message:", decrypted_message)
