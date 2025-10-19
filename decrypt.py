import sys
from core import decrypt_folder_with_key
def main():
    args = sys.argv[1:]
    if len(args) != 2:
        print("Usage: python decrypt.py <key> <salt>")
        sys.exit(1)
    print("Decrypting folder with provided key and salt...")
    decrypt_folder_with_key("Encrypted Book", "The Book", args[0], args[1])


if __name__ == "__main__":
    main()