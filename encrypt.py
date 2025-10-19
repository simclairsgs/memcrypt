import sys
from core import encrypt_folder_with_key
def main():
    args = sys.argv[1:]
    if len(args) != 2:
        print("Usage: python encrypt.py <key> <salt>")
        sys.exit(1)
    print("Encrypting folder with provided key and salt...")
    encrypt_folder_with_key("The Book", "Encrypted Book", args[0], args[1])
    print("Encryption complete. Encrypted folder created as 'Encrypted Book'.")
    # delete the original folder after encryption
    import shutil
    shutil.rmtree("The Book")


if __name__ == "__main__":
    main()