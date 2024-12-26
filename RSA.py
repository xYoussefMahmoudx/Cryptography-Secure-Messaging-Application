from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA key pair
def generate_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# Encrypt a message using the public key
def encrypt(public_key, plaintext):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


# Decrypt a message using the private key
def decrypt(private_key, ciphertext):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


# Example usage
if __name__ == "__main__":
    print("Generating RSA key pair...")
    private_key, public_key = generate_keypair()
    print("Public Key:", public_key.decode('utf-8'))
    print("Private Key:", private_key.decode('utf-8'))

    message = "Secure Communication Suite"
    print("\nOriginal Message:", message)


    encrypted_message = encrypt(public_key, message)
    print("\nEncrypted Message:", encrypted_message)

    decrypted_message = decrypt(private_key, encrypted_message)
    print("\nDecrypted Message:", decrypted_message)
