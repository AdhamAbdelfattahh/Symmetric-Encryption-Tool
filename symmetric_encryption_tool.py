from cryptography.fernet import Fernet

def generate_key():
    """Generate a new Fernet key and save it to a file."""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved as 'secret.key'")

def load_key():
    """Load the previously generated key from the file."""
    return open("secret.key", "rb").read()

def encrypt_message(message, key):
    """Encrypt a message using the provided key."""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return encrypted

def decrypt_message(encrypted_message, key):
    """Decrypt a message using the provided key."""
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_message).decode()
    return decrypted

def main():
    while True:
        choice = input("Type 'generate' to create a new key, 'encrypt' to encrypt a message, or 'decrypt' to decrypt a message (or 'exit' to quit): ").lower()
        
        if choice == 'generate':
            generate_key()
        elif choice == 'encrypt':
            message = input("Enter your message: ")
            key = load_key()
            encrypted_message = encrypt_message(message, key)
            print(f"Encrypted message: {encrypted_message}")
        elif choice == 'decrypt':
            encrypted_message = input("Enter the encrypted message: ").encode()
            key = load_key()
            decrypted_message = decrypt_message(encrypted_message, key)
            print(f"Decrypted message: {decrypted_message}")
        elif choice == 'exit':
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
