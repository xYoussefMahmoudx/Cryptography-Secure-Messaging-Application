# Cryptography-Secure-Messaging-Application.

## Introduction

The **Cryptography Secure Messaging Application.** is a Python-based application designed to provide a secure communication system by implementing robust cryptographic techniques and authentication mechanisms. The project focuses on ensuring confidentiality, integrity, and secure key management in the communication process. By utilizing encryption, hashing, and public-key cryptosystems, the system guarantees that the transmitted data remains safe from unauthorized access and tampering.

## Project Overview

This system allows users to exchange secure messages by verifying user credentials, encrypting the messages with a block cipher, hashing the plaintext for integrity verification, and securely managing keys using a public-key cryptosystem. It is intended to provide a high level of data security for sensitive communications.

### Key Features:
- **User Authentication:** Verifies user credentials before allowing access.
- **Encryption:** Encrypts plaintext messages using a block cipher.
- **Hashing:** Generates a hash for plaintext to verify data integrity.
- **Key Management:** Securely encrypts and decrypts symmetric keys using a public-key cryptosystem.
- **Secure Communication:** Ensures secure transmission of messages over the internet.

## Report

For detailed information, including the technical documentation and implementation specifics, please refer to the [Full Project Report](https://drive.google.com/file/d/1b2xBOU0MaO8WOyNxk2CYTH0mzyOogxmi/view?usp=sharing) .

## Run the Application:

Navigate to the project directory and run the following command to start the server:

```console
python peer.py <port_number>
```

Replace <port_number> with the desired port number (e.g., 5000 for localhost).
