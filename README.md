# ShareIt - Encrypted File Transfer Tool

A simple Python-based file sharing application that allows secure transfer of files over a local network using AES encryption.

## Features

- 🔒 **Encrypted file transfer** using AES-256 encryption
- 📊 **Progress tracking** with real-time transfer status
- 🔄 **Resume capability** for interrupted transfers
- 🌐 **Network file sharing** between devices on the same network
- 📁 **Support for any file type**

## Requirements

- Python 3.6+
- Required packages (install via `pip install -r requirements.txt`):
  - `pycryptodome` - For AES encryption

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Method 1: Using the main app (Interactive)

Run the main application:
```bash
python app.py
```

Choose your option:
- Enter `1` to **receive** files (run as server)
- Enter `0` to **send** files (run as client)

### Method 2: Using individual scripts

#### To receive files (Server):
```bash
python receiver.py
```

#### To send files (Client):
```bash
python sender.py
```

When prompted:
- Enter the server IP address (or press Enter for localhost)
- Enter the path to the file you want to send

## How it works

1. **Receiver** starts a server on port `6996` and waits for connections
2. **Sender** connects to the receiver and sends file metadata
3. Files are encrypted using AES-256 with PBKDF2 key derivation
4. Data is transferred in chunks with progress tracking
5. Files are automatically decrypted on the receiver side

## Security

- Uses AES-256 encryption in CBC mode
- PBKDF2 key derivation with 100,000 iterations
- Files are encrypted during transmission and decrypted on arrival

## Default Settings

- **Port**: 6996
- **Encryption Key**: "vardhanSecretKey" (can be modified in source)
- **Buffer Size**: 4096 bytes per chunk

## Notes

- Make sure both sender and receiver are on the same network
- Firewall settings may need to be configured to allow connections on port 6996
- The default encryption key should be changed for production use

## License

This project is open source and available under the MIT License.
