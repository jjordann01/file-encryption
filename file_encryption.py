from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
import sys


def encrypt_file(file_path, key):
    """Encrypt the file with AES encryption."""
    # Generate a random 128-bit IV
    iv = os.urandom(16)
    
    # Read the file content
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Pad the data to be multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Initialize AES cipher with the provided key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted data to a new file
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + encrypted_data)

    print(f"File encrypted successfully! Saved as {encrypted_file_path}")


def decrypt_file(file_path, key):
    """Decrypt the file using AES encryption."""
    # Read the encrypted file data
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Extract the IV from the first 16 bytes
    iv = file_data[:16]
    encrypted_data = file_data[16:]

    # Initialize AES cipher with the provided key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Save the decrypted data to a new file
    decrypted_file_path = file_path.replace(".enc", ".dec")
    with open(decrypted_file_path, 'wb') as f:
        f.write(unpadded_data)

    print(f"File decrypted successfully! Saved as {decrypted_file_path}")


def main():
    """Main function to handle encryption and decryption."""
    if len(sys.argv) < 4:
        print("Usage: python file_encryption.py <encrypt|decrypt> <file_path> <key>")
        sys.exit(1)

    action = sys.argv[1]
    file_path = sys.argv[2]
    key = sys.argv[3].encode()

    if len(key) != 16:
        print("Key must be exactly 16 bytes long.")
        sys.exit(1)

    if action == 'encrypt':
        encrypt_file(file_path, key)
    elif action == 'decrypt':
        decrypt_file(file_path, key)
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
