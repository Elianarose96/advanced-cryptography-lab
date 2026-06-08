from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    # Combine nonce, tag, and ciphertext for storage/transmission
    encrypted_package = cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted_package).decode('utf-8')

def decrypt_aes(encrypted_b64, key):
    encrypted_data = base64.b64decode(encrypted_b64)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode('utf-8')

# Main demonstration
if __name__ == "__main__":
    # Generate a random 256-bit (32 bytes) AES key
    key = get_random_bytes(32)
    
    print("=" * 50)
    print("ADVANCED CRYPTOGRAPHY - AES-256 DEMO")
    print("=" * 50)
    
    original_message = "Advanced Cryptography - Secure Communication Test"
    print(f"\nOriginal Message: {original_message}")
    print(f"AES Key (hex): {key.hex()}")
    
    # Encrypt
    encrypted = encrypt_aes(original_message, key)
    print(f"\nEncrypted (Base64): {encrypted}")
    
    # Decrypt
    decrypted = decrypt_aes(encrypted, key)
    print(f"\nDecrypted Message: {decrypted}")
    
    print(f"\n✓ SUCCESS: Encryption and decryption working!")
    print(f"✓ Mode: AES-256-GCM (Authenticated Encryption)")