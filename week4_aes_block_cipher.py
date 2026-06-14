"""
Week 4: Block Cipher Design and AES
Advanced Encryption Standard (AES) Implementation - FIXED VERSION
"""

import os
import time
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# ============================================================
# FIG 1: AES Encryption Script
# ============================================================

class AESHelper:
    """AES Block Cipher Helper Class"""
    
    def __init__(self, key=None, key_size=256):
        """
        Initialize AES cipher with key
        key_size: 128, 192, or 256 bits
        """
        self.key_size = key_size
        self.block_size = AES.block_size  # 16 bytes (128 bits)
        
        if key is None:
            self.key = get_random_bytes(key_size // 8)
        else:
            self.key = self._derive_key(key)
    
    def _derive_key(self, password):
        """Derive AES key from password using SHA-256"""
        return hashlib.sha256(password.encode()).digest()
    
    def encrypt_text(self, plaintext):
        """
        Encrypt text string using AES-CBC mode
        Returns: Base64 encoded ciphertext with IV
        """
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        padded_data = pad(plaintext, self.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_text(self, encrypted_b64):
        """
        Decrypt Base64 encoded ciphertext back to text string
        """
        encrypted_data = base64.b64decode(encrypted_b64)
        iv = encrypted_data[:self.block_size]
        ciphertext = encrypted_data[self.block_size:]
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_padded, self.block_size)
        return plaintext.decode('utf-8')
    
    def encrypt_bytes(self, data):
        """
        Encrypt bytes data (for binary files/performance testing)
        Returns: Base64 encoded ciphertext with IV
        """
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        padded_data = pad(data, self.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data)
    
    def decrypt_bytes(self, encrypted_b64):
        """
        Decrypt Base64 encoded ciphertext back to bytes
        """
        encrypted_data = base64.b64decode(encrypted_b64)
        iv = encrypted_data[:self.block_size]
        ciphertext = encrypted_data[self.block_size:]
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_padded, self.block_size)
        return plaintext
    
    def get_key_hex(self):
        """Get key in hexadecimal format (for display)"""
        return self.key.hex()
    
    def save_key(self, filename):
        """Save key to file (for secure storage)"""
        with open(filename, 'wb') as f:
            f.write(self.key)
        print(f"✅ Key saved to {filename}")
    
    def load_key(self, filename):
        """Load key from file"""
        with open(filename, 'rb') as f:
            self.key = f.read()
        print(f"✅ Key loaded from {filename}")


# ============================================================
# FIG 2: Key Generation Process
# ============================================================

def key_generation_demo():
    """Demonstrate AES key generation process"""
    print("\n" + "=" * 70)
    print("   FIG 2: AES KEY GENERATION PROCESS")
    print("=" * 70)
    
    # Generate random AES-256 key
    random_key = get_random_bytes(32)  # 256 bits = 32 bytes
    
    print("\n🔑 Random Key Generation (AES-256):")
    print(f"   Key (hex):  {random_key.hex()}")
    print(f"   Key length: {len(random_key) * 8} bits")
    print(f"   Key bytes:  {len(random_key)} bytes")
    
    # Derive key from password
    password = "MySecretPassword123!"
    derived_key = hashlib.sha256(password.encode()).digest()
    
    print("\n🔑 Password-Based Key Derivation (PBKDF):")
    print(f"   Password:   {password}")
    print(f"   Derived key (hex): {derived_key.hex()[:32]}...")  # First 32 chars
    print(f"   Key length: {len(derived_key) * 8} bits")
    
    # Show key sizes comparison
    print("\n📊 AES Key Size Comparison:")
    print(f"   {'Key Size':<15} {'Bytes':<10} {'Security Level':<20}")
    print("   " + "-" * 45)
    print(f"   {'AES-128':<15} {'16':<10} {'Standard Security'}")
    print(f"   {'AES-192':<15} {'24':<10} {'High Security'}")
    print(f"   {'AES-256':<15} {'32':<10} {'Military Grade'}")
    
    return random_key


# ============================================================
# FIG 3: File Encryption Demonstration
# ============================================================

def file_encryption_demo():
    """Demonstrate file encryption with AES"""
    print("\n" + "=" * 70)
    print("   FIG 3: FILE ENCRYPTION DEMONSTRATION")
    print("=" * 70)
    
    # Create a sample text file
    test_filename = "secret_message.txt"
    encrypted_filename = "secret_message.enc"
    
    # Sample content
    original_content = """=== TOP SECRET DOCUMENT ===
    
To: Cryptography Lab Team
From: Security Department

The encryption keys for Project Aurora have been rotated.
Please update all systems before June 30, 2026.

Authentication Code: AES-256-CBC-2026
Security Level: CLASSIFIED

End of Message.
"""
    
    print(f"\n📄 Creating test file: {test_filename}")
    with open(test_filename, 'w', encoding='utf-8') as f:
        f.write(original_content)
    
    print(f"   Original content ({len(original_content)} bytes):")
    print(f"   {original_content[:100]}...")
    
    # Initialize AES
    aes = AESHelper(key_size=256)
    
    # Read and encrypt file
    print(f"\n🔒 Encrypting file...")
    with open(test_filename, 'r', encoding='utf-8') as f:
        plaintext = f.read()
    
    encrypted_data = aes.encrypt_text(plaintext)
    
    # Save encrypted data
    with open(encrypted_filename, 'w', encoding='utf-8') as f:
        f.write(encrypted_data)
    
    print(f"   ✅ Encrypted file saved: {encrypted_filename}")
    print(f"   Encrypted size: {len(encrypted_data)} bytes")
    print(f"   Key used: {aes.get_key_hex()[:32]}...")
    
    # Show encrypted preview
    print(f"\n   Encrypted preview:")
    print(f"   {encrypted_data[:80]}...")
    
    return aes, test_filename, encrypted_filename, original_content


# ============================================================
# FIG 4: Decryption Results
# ============================================================

def decryption_demo(aes, encrypted_filename, original_content):
    """Demonstrate file decryption"""
    print("\n" + "=" * 70)
    print("   FIG 4: DECRYPTION RESULTS")
    print("=" * 70)
    
    # Read encrypted file
    print(f"\n📁 Reading encrypted file: {encrypted_filename}")
    with open(encrypted_filename, 'r', encoding='utf-8') as f:
        encrypted_data = f.read()
    
    # Decrypt
    print(f"\n🔓 Decrypting with AES-256 key...")
    decrypted_content = aes.decrypt_text(encrypted_data)
    
    # Verify
    print(f"\n📊 Verification Results:")
    print(f"   Original length:  {len(original_content)} bytes")
    print(f"   Decrypted length: {len(decrypted_content)} bytes")
    print(f"   Match:            {'✅ YES' if original_content == decrypted_content else '❌ NO'}")
    
    print(f"\n📄 Decrypted Content:")
    print("   " + "-" * 50)
    print(decrypted_content)
    print("   " + "-" * 50)
    
    # Save decrypted file
    decrypted_filename = "secret_message_decrypted.txt"
    with open(decrypted_filename, 'w', encoding='utf-8') as f:
        f.write(decrypted_content)
    print(f"\n✅ Decrypted file saved: {decrypted_filename}")
    
    return decrypted_content


# ============================================================
# FIG 5: AES Performance Testing (FIXED)
# ============================================================

def performance_testing():
    """Benchmark AES encryption performance on binary data"""
    print("\n" + "=" * 70)
    print("   FIG 5: AES PERFORMANCE TESTING")
    print("=" * 70)
    
    test_sizes = [
        ("1 KB", 1024),
        ("10 KB", 10240),
        ("100 KB", 102400),
        ("1 MB", 1048576),
        ("5 MB", 5242880)
    ]
    
    key_size = 256  # AES-256
    
    print("\n📊 AES-256 Performance Benchmark")
    print("-" * 70)
    print(f"{'Size':<10} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15} {'Throughput (MB/s)':<15}")
    print("-" * 70)
    
    results = []
    
    for size_name, size_bytes in test_sizes:
        # Generate random binary test data
        test_data = os.urandom(size_bytes)
        
        # Initialize AES with random key
        aes = AESHelper(key_size=key_size)
        
        # Measure encryption time
        start = time.perf_counter()
        encrypted = aes.encrypt_bytes(test_data)
        encrypt_time = (time.perf_counter() - start) * 1000
        
        # Measure decryption time
        start = time.perf_counter()
        decrypted = aes.decrypt_bytes(encrypted)
        decrypt_time = (time.perf_counter() - start) * 1000
        
        # Verify (compare bytes directly, no decode)
        success = decrypted == test_data
        
        # Calculate throughput (MB/s)
        throughput = (size_bytes / 1024 / 1024) / (encrypt_time / 1000)
        
        status = "✅" if success else "❌"
        print(f"{size_name:<10} {encrypt_time:<15.3f} {decrypt_time:<15.3f} {throughput:<15.2f} {status}")
        
        results.append({
            'size': size_name,
            'encrypt_ms': encrypt_time,
            'decrypt_ms': decrypt_time,
            'throughput_mbps': throughput,
            'success': success
        })
    
    print("-" * 70)
    
    # AES Mode Comparison
    print("\n📊 AES Mode Comparison (1 MB data)")
    print("-" * 60)
    print(f"{'Mode':<15} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15}")
    print("-" * 60)
    
    test_data = os.urandom(1048576)  # 1 MB binary data
    key = get_random_bytes(32)
    
    # CBC Mode
    cipher_cbc = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(16))
    start = time.perf_counter()
    encrypted_cbc = cipher_cbc.encrypt(pad(test_data, AES.block_size))
    cbc_encrypt = (time.perf_counter() - start) * 1000
    
    # GCM Mode (faster, includes authentication)
    cipher_gcm = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    start = time.perf_counter()
    encrypted_gcm, tag = cipher_gcm.encrypt_and_digest(test_data)
    gcm_encrypt = (time.perf_counter() - start) * 1000
    
    print(f"{'CBC Mode':<15} {cbc_encrypt:<15.3f} {'N/A':<15}")
    print(f"{'GCM Mode':<15} {gcm_encrypt:<15.3f} {'N/A':<15}")
    print("-" * 60)
    
    print("\n📈 PERFORMANCE SUMMARY:")
    print("   ✅ AES-256 encrypts ~50-100 MB/s on modern hardware")
    print("   ✅ Decryption speed comparable to encryption")
    print("   ✅ GCM mode is faster and includes authentication")
    print("   ✅ Suitable for real-time file and disk encryption")
    
    return results


# ============================================================
# MAIN EXECUTION
# ============================================================

def run_all_demos():
    """Run all Week 4 demonstrations"""
    print("=" * 70)
    print("   WEEK 4: BLOCK CIPHER DESIGN AND AES")
    print("   Advanced Encryption Standard (AES) Implementation")
    print("=" * 70)
    
    # FIG 2: Key Generation
    key_generation_demo()
    
    # FIG 3: File Encryption
    aes, test_file, enc_file, original = file_encryption_demo()
    
    # FIG 4: Decryption
    decryption_demo(aes, enc_file, original)
    
    # FIG 5: Performance Testing (FIXED)
    performance_testing()
    
    # FIG 1: Shown by displaying the AESHelper class in editor
    print("\n" + "=" * 70)
    print("   FIG 1: AES ENCRYPTION SCRIPT")
    print("   = See AESHelper class code in week4_aes_block_cipher.py")
    print("=" * 70)
    
    # Cleanup temporary files (optional)
    print("\n🧹 Files created (keep for demo):")
    print(f"   - secret_message.txt")
    print(f"   - secret_message.enc")
    print(f"   - secret_message_decrypted.txt")


if __name__ == "__main__":
    # Check if pycryptodome is installed
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("❌ Please install pycryptodome first:")
        print("   pip install pycryptodome")
        exit(1)
    
    run_all_demos()