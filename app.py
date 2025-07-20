import socket
import os
import tqdm
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

class ShareItApp:
    def __init__(self):
        self.PORT = 6996
        self.address = socket.gethostbyname(socket.gethostname())  # Default to the local machine
        self.KEY = 'vardhanSecretKey'  # Secret key for encryption 
        self.SALT = 'vardhanSalt'  # Salt for encryption
    
    def derive_key(self, password, salt):
        """Derive a 32-byte key from password and salt using PBKDF2"""
        return PBKDF2(password, salt.encode(), 32, count=100000)

    def encrypt_data(self, data, key):
        """Encrypt data using AES in CBC mode"""
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        # Pad data to be multiple of 16 bytes (AES block size)
        padding_length = AES.block_size - len(data) % AES.block_size
        padded_data = data + bytes([padding_length]) * padding_length
        encrypted_data = cipher.encrypt(padded_data)
        return bytes(iv) + encrypted_data  # Prepend IV to encrypted data

    def decrypt_data(self, encrypted_data, key):
        """Decrypt data using AES in CBC mode"""
        iv = encrypted_data[:16]  # First 16 bytes are IV
        encrypted_content = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_content)
        # Remove padding
        padding_length = decrypted_data[-1]
        return decrypted_data[:-padding_length]

    def start(self):
        print(f"Starting ShareItApp on {self.address}:{self.PORT}")
        self.server_address = (self.address, self.PORT) 
        choice = input("Do you want to run as Receive (1) or Send (0)? ")
        if choice == '1':
            self.run_server()
        elif choice == '0':
            self.run_client()
        else:
            print("Invalid choice. Exiting.")
            exit() 
    
    def run_server(self):
        """Run as server (receiver) to accept file transfers"""
        # Derive decryption key
        decryption_key = self.derive_key(self.KEY, self.SALT)
        
        server_address = (self.address, self.PORT)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            s.bind(server_address)
            s.listen(1)
            print(f"Server listening on {server_address[0]}:{server_address[1]}")
            
            connection, client_address = s.accept()
            print(f"Connection established with {client_address}")
            
            # Receive combined metadata and split it
            metadata = connection.recv(1024).decode()
            try:
                fileName, totalSize = metadata.split("|||")
                totalSize = int(totalSize)
            except ValueError:
                print("❌ Error parsing metadata.")
                connection.close()
                s.close()
                return
            
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
                    return
            
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
                        decrypted_data = self.decrypt_data(encrypted_data, decryption_key)
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
            
        except Exception as e:
            print(f"❌ Server error: {e}")
            s.close()
    
    def run_client(self):
        """Run as client (sender) to send file transfers"""
        address = input("Enter the server address (default is localhost): ") or 'localhost'
        server_address = (address, self.PORT)
        
        filePath = input("Enter the file path to send: ")
        
        if not os.path.exists(filePath):
            print("❌ File not found!")
            return
            
        fileSize = os.path.getsize(filePath)
        fileName = os.path.basename(filePath)
        print(f"Sending file: {fileName} of size {fileSize} bytes")
        
        # Derive encryption key
        encryption_key = self.derive_key(self.KEY, self.SALT)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            sock.connect(server_address)
            print(f"Connected to server at {server_address[0]}:{server_address[1]}")
            
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
                    encrypted_data = self.encrypt_data(data, encryption_key)
                    
                    # Send the size of encrypted data first, then the encrypted data
                    encrypted_size = len(encrypted_data)
                    sock.sendall(encrypted_size.to_bytes(4, 'big'))  # Send size as 4-byte big-endian
                    sock.sendall(encrypted_data)
                    
                    bytesSent += len(data)  # Original data size for progress
                    print(f"\rSent {bytesSent}/{fileSize} bytes (encrypted)", end='')
            
            print("\nFile transfer complete.")
            sock.close()
            print('Connection closed. Client shutting down.')
            
        except Exception as e:
            print(f"❌ Client error: {e}")
            sock.close()



shareIt = ShareItApp()  
shareIt.start()
