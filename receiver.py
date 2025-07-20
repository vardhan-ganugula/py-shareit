import socket 
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Define constants (must match sender)
KEY = 'vardhanSecretKey'  # Secret key for encryption 
SALT = 'vardhanSalt'  # Salt for encryption

def derive_key(password, salt):
    """Derive a 32-byte key from password and salt using PBKDF2"""
    return PBKDF2(password, salt.encode(), 32, count=100000)

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES in CBC mode"""
    iv = encrypted_data[:16]  # First 16 bytes are IV
    encrypted_content = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_content)
    # Remove padding
    padding_length = decrypted_data[-1]
    return decrypted_data[:-padding_length]

serverAddress = ('localhost', 6996)

# Derive decryption key
decryption_key = derive_key(KEY, SALT)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.bind(serverAddress)
s.listen(1)

print(f"Server listening on {serverAddress[0]}:{serverAddress[1]}")
connection, clientAddress = s.accept() 
print(f"Connection established with {clientAddress}")

# Receive combined metadata and split it
metadata = connection.recv(1024).decode()
try:
    fileName, totalSize = metadata.split("|||")
    totalSize = int(totalSize)
except ValueError:
    print("❌ Error parsing metadata.")
    connection.close()
    s.close()
    exit()

print(f"Receiving file: {fileName}")
start = 0

if os.path.exists(fileName):
    choice = input(f"File {fileName} already exists. Do you want to overwrite it? (yes [1]/ no [0]): ")
    if choice == '0':
        start = os.path.getsize(fileName)
        print(f"Resuming from {start} bytes")
    elif choice == '1':
        os.remove(fileName)
        print(f"Overwriting {fileName}")
    else:
        print("Invalid choice. Exiting.")
        connection.close()
        s.close()
        exit()

# Send resume point to sender
connection.send(str(start).encode())

print(f"Total file size to receive: {totalSize} bytes")

with open(fileName, 'ab' if start > 0 else 'wb') as f:
    bytesReceived = start
    while bytesReceived < totalSize:
        # First receive the size of the encrypted data (4 bytes)
        size_data = connection.recv(4)
        if not size_data:
            break
        encrypted_size = int.from_bytes(size_data, 'big')
        
        # Then receive the encrypted data
        encrypted_data = b''
        while len(encrypted_data) < encrypted_size:
            chunk = connection.recv(encrypted_size - len(encrypted_data))
            if not chunk:
                break
            encrypted_data += chunk
        
        if not encrypted_data:
            break
            
        # Decrypt the data
        try:
            decrypted_data = decrypt_data(encrypted_data, decryption_key)
            f.write(decrypted_data)
            bytesReceived += len(decrypted_data)
            print(f"\rReceived {bytesReceived}/{totalSize} bytes (decrypted)", end='')
        except Exception as e:
            print(f"\n❌ Decryption error: {e}")
            break

print("\nFile transfer complete.")
connection.close()
s.close()
print('Connection closed. Server shutting down.')
