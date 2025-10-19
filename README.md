# Folder Encryption with AES-GCM-128

This project provides Python code to encrypt and decrypt entire folders using AES-GCM-128 encryption.

## Features

- **AES-GCM-128 Encryption**: Uses industry-standard AES encryption in GCM mode with 128-bit keys
- **Folder Structure Preservation**: Maintains the original directory structure during encryption/decryption
- **Metadata Management**: Stores encryption metadata and folder structure in JSON format
- **Key Derivation**: Uses PBKDF2 with SHA-256 for secure key derivation from passwords
- **Integrity Protection**: GCM mode provides built-in authentication and integrity checking

## Installation

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
## Usage
    ```
    python encrypt.py <key> <salt>
    python decrypt.py <key> <salt>
    ```
