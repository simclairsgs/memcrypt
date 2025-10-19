import os
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Union
import base64

# core.py
# @author: George Simclair Sam
# This module provides functionality to encrypt and decrypt entire folders using AES-GCM-128.
# @version: 1.0
# Date: 2025-10-19

class FolderEncryptor:
    """
    A class to encrypt and decrypt entire folders using AES-GCM-128.
    """
    
    def __init__(self, key: Union[str, bytes], salt: Union[str, bytes]):
        """
        Initialize the encryptor with a key and salt.
        
        Args:
            key: The encryption key (string or bytes)
            salt: The salt for key derivation (string or bytes)
        """
        self.salt = salt.encode('utf-8') if isinstance(salt, str) else salt
        self.key = self._derive_key(key)
        self.aesgcm = AESGCM(self.key)
    
    def _derive_key(self, password: Union[str, bytes]) -> bytes:
        """
        Derive a 128-bit key from password using PBKDF2.
        
        Args:
            password: The password to derive key from
            
        Returns:
            128-bit derived key
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,  # 128 bits
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def _encrypt_file(self, file_path: Path) -> tuple[bytes, bytes]:
        """
        Encrypt a single file.
        
        Args:
            file_path: Path to the file to encrypt
            
        Returns:
            Tuple of (encrypted_data, nonce)
        """
        with open(file_path, 'rb') as f:
            data = f.read()
        
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        encrypted_data = self.aesgcm.encrypt(nonce, data, None)
        
        return encrypted_data, nonce
    
    def _decrypt_file(self, encrypted_data: bytes, nonce: bytes) -> bytes:
        """
        Decrypt encrypted file data.
        
        Args:
            encrypted_data: The encrypted file data
            nonce: The nonce used for encryption
            
        Returns:
            Decrypted file data
        """
        return self.aesgcm.decrypt(nonce, encrypted_data, None)
    
    def encrypt_folder(self, source_folder: Union[str, Path], 
                      destination_folder: Union[str, Path]) -> None:
        """
        Encrypt an entire folder and save to destination.
        
        Args:
            source_folder: Path to the source folder to encrypt
            destination_folder: Path to the destination folder for encrypted files
        """
        source_path = Path(source_folder)
        dest_path = Path(destination_folder)
        
        if not source_path.exists():
            raise FileNotFoundError(f"Source folder '{source_folder}' does not exist")
        
        if not source_path.is_dir():
            raise ValueError(f"Source '{source_folder}' is not a directory")
        
        # Create destination directory if it doesn't exist
        dest_path.mkdir(parents=True, exist_ok=True)
        
        # Dictionary to store folder structure and encryption metadata
        folder_metadata = {
            'folder_structure': {},
            'encryption_info': {
                'algorithm': 'AES-GCM-128',
                'salt': base64.b64encode(self.salt).decode('utf-8')
            }
        }
        
        # Walk through all files in the source folder
        for root, dirs, files in os.walk(source_path):
            root_path = Path(root)
            
            # Calculate relative path from source folder
            rel_path = root_path.relative_to(source_path)
            
            # Create corresponding directory structure in destination
            dest_subdir = dest_path / rel_path
            dest_subdir.mkdir(parents=True, exist_ok=True)
            
            # Initialize folder structure for this directory
            if str(rel_path) not in folder_metadata['folder_structure']:
                folder_metadata['folder_structure'][str(rel_path)] = {
                    'directories': dirs.copy(),
                    'files': {}
                }
            
            # Encrypt each file
            for file_name in files:
                source_file = root_path / file_name
                
                try:
                    # Encrypt the file
                    encrypted_data, nonce = self._encrypt_file(source_file)
                    
                    # Save encrypted file with .enc extension
                    encrypted_file_name = f"{file_name}.enc"
                    encrypted_file_path = dest_subdir / encrypted_file_name
                    
                    with open(encrypted_file_path, 'wb') as f:
                        f.write(encrypted_data)
                    
                    # Store metadata
                    folder_metadata['folder_structure'][str(rel_path)]['files'][file_name] = {
                        'encrypted_name': encrypted_file_name,
                        'nonce': base64.b64encode(nonce).decode('utf-8'),
                        'original_size': source_file.stat().st_size
                    }
                    
                    print(f"Encrypted: {source_file} -> {encrypted_file_path}")
                    
                except Exception as e:
                    print(f"Error encrypting {source_file}: {e}")
                    continue
        
        # Save metadata file
        metadata_file = dest_path / 'folder_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(folder_metadata, f, indent=2)
        
        print(f"Folder encryption completed. Metadata saved to {metadata_file}")
    
    def decrypt_folder(self, encrypted_folder: Union[str, Path], 
                      destination_folder: Union[str, Path]) -> None:
        """
        Decrypt an encrypted folder and restore original structure.
        
        Args:
            encrypted_folder: Path to the encrypted folder
            destination_folder: Path to restore decrypted files
        """
        encrypted_path = Path(encrypted_folder)
        dest_path = Path(destination_folder)
        
        if not encrypted_path.exists():
            raise FileNotFoundError(f"Encrypted folder '{encrypted_folder}' does not exist")
        
        # Read metadata
        metadata_file = encrypted_path / 'folder_metadata.json'
        if not metadata_file.exists():
            raise FileNotFoundError(f"Metadata file not found in '{encrypted_folder}'")
        
        with open(metadata_file, 'r') as f:
            folder_metadata = json.load(f)
        
        # Verify salt matches
        stored_salt = base64.b64decode(folder_metadata['encryption_info']['salt'])
        if stored_salt != self.salt:
            raise ValueError("Salt mismatch - wrong key or corrupted metadata")
        
        # Create destination directory
        dest_path.mkdir(parents=True, exist_ok=True)
        
        # Restore folder structure and decrypt files
        for rel_path_str, folder_info in folder_metadata['folder_structure'].items():
            rel_path = Path(rel_path_str)
            
            # Create directory structure
            dest_subdir = dest_path / rel_path
            dest_subdir.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories
            for dir_name in folder_info['directories']:
                (dest_subdir / dir_name).mkdir(exist_ok=True)
            
            # Decrypt files
            for original_name, file_info in folder_info['files'].items():
                encrypted_file_path = encrypted_path / rel_path / file_info['encrypted_name']
                decrypted_file_path = dest_subdir / original_name
                
                try:
                    # Read encrypted data
                    with open(encrypted_file_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    # Get nonce from metadata
                    nonce = base64.b64decode(file_info['nonce'])
                    
                    # Decrypt the data
                    decrypted_data = self._decrypt_file(encrypted_data, nonce)
                    
                    # Save decrypted file
                    with open(decrypted_file_path, 'wb') as f:
                        f.write(decrypted_data)
                    
                    print(f"Decrypted: {encrypted_file_path} -> {decrypted_file_path}")
                    
                except Exception as e:
                    print(f"Error decrypting {encrypted_file_path}: {e}")
                    continue
        
        print(f"Folder decryption completed. Files restored to {dest_path}")


def encrypt_folder_with_key(source_folder: str, destination_folder: str, 
                           key: str, salt: str) -> None:
    """
    Convenience function to encrypt a folder with given key and salt.
    
    Args:
        source_folder: Path to source folder to encrypt
        destination_folder: Path to destination for encrypted files
        key: Encryption key
        salt: Salt for key derivation
    """
    encryptor = FolderEncryptor(key, salt)
    encryptor.encrypt_folder(source_folder, destination_folder)


def decrypt_folder_with_key(encrypted_folder: str, destination_folder: str,
                           key: str, salt: str) -> None:
    """
    Convenience function to decrypt a folder with given key and salt.
    
    Args:
        encrypted_folder: Path to encrypted folder
        destination_folder: Path to destination for decrypted files
        key: Decryption key (must match encryption key)
        salt: Salt for key derivation (must match encryption salt)
    """
    encryptor = FolderEncryptor(key, salt)
    encryptor.decrypt_folder(encrypted_folder, destination_folder)


# Example usage
if __name__ == "__main__":
    # Example parameters
    source_folder = "The Book"
    encrypted_folder = "encrypted_book"
    decrypted_folder = "decrypted_book"
    key = "my_secret_password"
    salt = "my_salt_value"
    
    try:
        # Encrypt the folder
        print("Encrypting folder...")
        encrypt_folder_with_key(source_folder, encrypted_folder, key, salt)
        
        # Decrypt the folder
        print("\nDecrypting folder...")
        decrypt_folder_with_key(encrypted_folder, decrypted_folder, key, salt)
        
    except Exception as e:
        print(f"Error: {e}")
