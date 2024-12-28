import unittest
import logging
from Crypto.Random import get_random_bytes
from RSA import encrypt, decrypt
from key_management import KeyManagement
from hashing import HashingModule
from block_cypher import AESEncryption

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        logger.info("Setting up test environment for integration tests...")
        # Key management setup
        self.key_manager = KeyManagement()
        self.user_id = "integration_user"
        self.password = "integration_password"
        
        # Symmetric key setup
        self.symmetric_key = self.key_manager.generate_symmetric_key()
        
        # RSA key pair
        self.rsa_private_key, self.rsa_public_key = self.key_manager.generate_rsa_key_pair()
        self.key_manager.save_private_key(self.rsa_private_key, self.user_id, self.password)
        self.key_manager.save_public_key(self.rsa_public_key, self.user_id)

        # AES encryption setup
        self.aes = AESEncryption(self.symmetric_key)

        # Test data
        self.plaintext = "Integration testing for secure communication"
        self.hashed_plaintext = HashingModule.generate_hash(self.plaintext)

    def tearDown(self):
        logger.info("Cleaning up after integration tests...")
        self.key_manager.delete_private_key(self.user_id)
        self.key_manager.delete_public_key(self.user_id)

    def test_key_management_with_block_cipher(self):
        logger.info("Testing Key Management with Block Cipher...")
        # Encrypt plaintext using AES
        encrypted_data = self.aes.encrypt(self.plaintext)
        logger.info(f"Encrypted data: {encrypted_data}")

        # Decrypt the ciphertext using AES
        decrypted_text = self.aes.decrypt(
            encrypted_data["ciphertext"],
            encrypted_data["tag"],
            encrypted_data["nonce"]
        )
        logger.info(f"Decrypted text: {decrypted_text}")
        
        self.assertEqual(self.plaintext, decrypted_text)
        logger.info("Key management with block cipher test passed.")

    def test_key_management_with_rsa(self):
        logger.info("Testing Key Management with RSA...")
        # Encrypt the symmetric key with RSA public key
        encrypted_symmetric_key = encrypt(self.rsa_public_key, self.symmetric_key)
        logger.info(f"Encrypted symmetric key: {encrypted_symmetric_key}")

        # Decrypt the symmetric key with RSA private key
        decrypted_symmetric_key = decrypt(self.rsa_private_key, encrypted_symmetric_key)
        logger.info(f"Decrypted symmetric key: {decrypted_symmetric_key}")

        self.assertEqual(self.symmetric_key, decrypted_symmetric_key)
        logger.info("Key management with RSA test passed.")

    def test_block_cipher_and_key_management_with_rsa(self):
        logger.info("Testing Block Cipher and Key Management with RSA...")
        # Encrypt plaintext using AES
        encrypted_data = self.aes.encrypt(self.plaintext)
        logger.info(f"Encrypted data: {encrypted_data}")

        # Encrypt the symmetric key with RSA public key
        encrypted_symmetric_key = encrypt(self.rsa_public_key, self.symmetric_key)
        logger.info(f"Encrypted symmetric key with RSA: {encrypted_symmetric_key}")

        # Decrypt the symmetric key with RSA private key
        decrypted_symmetric_key = decrypt(self.rsa_private_key, encrypted_symmetric_key)
        logger.info(f"Decrypted symmetric key: {decrypted_symmetric_key}")

        # Decrypt the ciphertext using the decrypted symmetric key (AES)
        aes_decryptor = AESEncryption(decrypted_symmetric_key)
        decrypted_text = aes_decryptor.decrypt(
            encrypted_data["ciphertext"],
            encrypted_data["tag"],
            encrypted_data["nonce"]
        )
        logger.info(f"Decrypted text: {decrypted_text}")

        self.assertEqual(self.plaintext, decrypted_text)
        logger.info("Block cipher and key management with RSA test passed.")

    def test_block_cipher_and_key_management_with_rsa_with_hashing(self):
        logger.info("Testing Block Cipher, Key Management with RSA, and Hashing...")
        # Hash the plaintext before encryption
        logger.info(f"Original plaintext: {self.plaintext}")
        logger.info(f"Hashed plaintext: {self.hashed_plaintext}")

        # Encrypt the plaintext using AES
        encrypted_data = self.aes.encrypt(self.plaintext)
        logger.info(f"Encrypted data: {encrypted_data}")

        # Encrypt the symmetric key with RSA public key
        encrypted_symmetric_key = encrypt(self.rsa_public_key, self.symmetric_key)
        logger.info(f"Encrypted symmetric key with RSA: {encrypted_symmetric_key}")

        # Decrypt the symmetric key with RSA private key
        decrypted_symmetric_key = decrypt(self.rsa_private_key, encrypted_symmetric_key)
        logger.info(f"Decrypted symmetric key: {decrypted_symmetric_key}")

        # Decrypt the ciphertext using the decrypted symmetric key (AES)
        aes_decryptor = AESEncryption(decrypted_symmetric_key)
        decrypted_text = aes_decryptor.decrypt(
            encrypted_data["ciphertext"],
            encrypted_data["tag"],
            encrypted_data["nonce"]
        )
        logger.info(f"Decrypted text: {decrypted_text}")

        # Hash the decrypted text and verify it matches the original hash
        decrypted_text_hash = HashingModule.generate_hash(decrypted_text)
        self.assertEqual(self.hashed_plaintext, decrypted_text_hash)
        logger.info("Block cipher, key management with RSA, and hashing test passed.")

if __name__ == "__main__":
    unittest.main()
