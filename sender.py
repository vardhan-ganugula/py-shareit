import socket 
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib

# Define constants

PORT = 6996 
KEY = 'vardhanSecretKey'  # Secret key for encryption 
SALT = 'vardhanSalt'  # Salt for encryption

def derive_key(password, salt):
    """Derive a 32-byte key from password and salt using PBKDF2"""
    return PBKDF2(password, salt.encode(), 32, count=100000)

def encrypt_data(data, key):
    """Encrypt data using AES in CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    # Pad data to be multiple of 16 bytes (AES block size)
    padding_length = AES.block_size - len(data) % AES.block_size
    padded_data = data + bytes([padding_length]) * padding_length
    encrypted_data = cipher.encrypt(padded_data)
    return bytes(iv) + encrypted_data  # Prepend IV to encrypted data 



address = input("Enter the server address (default is localhost): ") or 'localhost'
serverAddress = (address, PORT)

filePath = input("Enter the file path to send: ") 
fileSize = os.path.getsize(filePath) 
fileName = os.path.basename(filePath) 
print(f"Sending file: {fileName} of size {fileSize} bytes")

# Derive encryption key
encryption_key = derive_key(KEY, SALT)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(serverAddress)
print(f"Connected to server at {serverAddress[0]}:{serverAddress[1]}")

# Send both filename and filesize together with delimiter
metadata = f"{fileName}|||{fileSize}"
sock.sendall(metadata.encode())

# Wait for the receiver to respond with the resume point
start = int(sock.recv(1024).decode())
print(f"Starting point for transfer: {start} bytes")

# Start sending file data from the resume point with encryption
with open(filePath, 'rb') as f:
    f.seek(start)
    bytesSent = start
    while bytesSent < fileSize:
        data = f.read(1024)
        if not data:
            break
        
        # Encrypt the data chunk
        encrypted_data = encrypt_data(data, encryption_key)
        
        # Send the size of encrypted data first, then the encrypted data
        encrypted_size = len(encrypted_data)
        sock.sendall(encrypted_size.to_bytes(4, 'big'))  # Send size as 4-byte big-endian
        sock.sendall(encrypted_data)
        
        bytesSent += len(data)  # Original data size for progress
        print(f"\rSent {bytesSent}/{fileSize} bytes (encrypted)", end='')

print("\nFile transfer complete.")
sock.close()
print('Connection closed. Client shutting down.')
