import unittest
import logging
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Import the necessary modules
from RSA import encrypt, decrypt
from key_management import KeyManagement
from hashing import HashingModule
from block_cypher import AESEncryption

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

class TestRSAEncryption(unittest.TestCase):
    def setUp(self):
        logger.info("Setting up RSA key pair for the test...")
        self.key_pair = RSA.generate(2048)
        self.public_key = self.key_pair.publickey().export_key()
        self.private_key = self.key_pair.export_key()
        self.plaintext = b"Secure communication test"

    def test_encrypt_decrypt(self):
        logger.info("Testing RSA encryption and decryption...")
        ciphertext = encrypt(self.public_key, self.plaintext)
        logger.info(f"Ciphertext: {ciphertext}")
        decrypted_text = decrypt(self.private_key, ciphertext)
        logger.info(f"Decrypted text: {decrypted_text}")
        self.assertEqual(self.plaintext, decrypted_text)


class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        logger.info("Setting up KeyManagement for the test...")
        self.key_manager = KeyManagement()
        self.user_id = "test_user"
        self.password = "secure_password"
        self.symmetric_key = self.key_manager.generate_symmetric_key()
        logger.info("Symmetric key generated successfully.")

    def test_symmetric_key_save_load(self):
        logger.info("Testing symmetric key save and load...")
        self.key_manager.save_symmetric_key(self.symmetric_key, self.user_id, self.password)
        logger.info("Symmetric key saved successfully.")
        loaded_key = self.key_manager.load_symmetric_key(self.user_id, self.password)
        logger.info("Symmetric key loaded successfully.")
        self.assertEqual(self.symmetric_key, loaded_key)

    def test_rsa_key_pair(self):
        logger.info("Testing RSA key pair generation and management...")
        private_key, public_key = self.key_manager.generate_rsa_key_pair()
        logger.info("RSA key pair generated successfully.")
        self.key_manager.save_private_key(private_key=private_key, user_id=self.user_id, password=self.password)
        self.key_manager.save_public_key(public_key=public_key, user_id=self.user_id)
        logger.info("RSA keys saved successfully.")
        self.assertTrue(private_key.startswith(b"-----BEGIN RSA PRIVATE KEY-----"))
        self.assertTrue(public_key.startswith(b"-----BEGIN PUBLIC KEY-----"))
        logger.info("RSA key validation passed.")
        self.key_manager.delete_private_key(self.user_id)
        self.key_manager.delete_public_key(self.user_id)
        logger.info("RSA keys deleted successfully.")


class TestHashingModule(unittest.TestCase):
    def test_generate_and_verify_hash(self):
        logger.info("Testing hash generation and verification...")
        data = "Secure communication test"
        hash_value = HashingModule.generate_hash(data)
        logger.info(f"Generated hash: {hash_value}")
        self.assertTrue(HashingModule.verify_hash(data, hash_value))
        logger.info("Hash verification passed.")


class TestAESEncryption(unittest.TestCase):
    def setUp(self):
        logger.info("Setting up AES encryption for the test...")
        self.key = get_random_bytes(32)
        self.aes = AESEncryption(self.key)
        self.plaintext = "Secure communication test"

    def test_encrypt_decrypt(self):
        logger.info("Testing AES encryption and decryption...")
        encrypted_data = self.aes.encrypt(self.plaintext)
        logger.info(f"Encrypted data: {encrypted_data}")
        decrypted_text = self.aes.decrypt(
            encrypted_data["ciphertext"],
            encrypted_data["tag"],
            encrypted_data["nonce"]
        )
        logger.info(f"Decrypted text: {decrypted_text}")
        self.assertEqual(self.plaintext, decrypted_text)
        logger.info("AES encryption and decryption passed.")


if __name__ == "__main__":
    unittest.main()
