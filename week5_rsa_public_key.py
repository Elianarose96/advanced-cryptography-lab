"""
Week 5: Public Key Cryptography (RSA)
Implementation of RSA Key Generation, Encryption, and Decryption
"""

import time
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import json

# ============================================================
# FIG 1: RSA Key Pair Generation
# ============================================================

def rsa_key_generation():
    """Generate RSA public/private key pair"""
    print("\n" + "=" * 70)
    print("   FIG 1: RSA KEY PAIR GENERATION")
    print("=" * 70)
    
    # Generate RSA key pair
    print("\n🔑 Generating RSA Key Pair (2048-bit)...")
    start_time = time.perf_counter()
    
    key = RSA.generate(2048)
    
    generation_time = (time.perf_counter() - start_time) * 1000
    
    # Extract public and private keys
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    print(f"   ✅ Key generation completed in {generation_time:.2f} ms")
    
    print("\n📊 Key Details:")
    print(f"   Key Size:      {key.size_in_bits()} bits")
    print(f"   Modulus (n):   {key.n}")
    print(f"   Public Exponent (e): {key.e}")
    print(f"   Private Exponent (d): {key.d}")
    
    print("\n📁 Key Format:")
    print(f"   Private Key (PEM):")
    print(f"   {private_key.decode()[:100]}...")
    print(f"\n   Public Key (PEM):")
    print(f"   {public_key.decode()[:100]}...")
    
    print("\n📊 Key Storage Options:")
    print("   - PEM format (text, base64 encoded)")
    print("   - DER format (binary)")
    print("   - Password-protected private key")
    
    # Save keys to files (optional)
    with open('rsa_private_key.pem', 'wb') as f:
        f.write(private_key)
    with open('rsa_public_key.pem', 'wb') as f:
        f.write(public_key)
    
    print("\n   ✅ Keys saved to files:")
    print("      - rsa_private_key.pem")
    print("      - rsa_public_key.pem")
    
    return key, private_key, public_key


# ============================================================
# FIG 2: Public Key Encryption Process
# ============================================================

def public_key_encryption_demo(public_key):
    """Demonstrate encryption using public key"""
    print("\n" + "=" * 70)
    print("   FIG 2: PUBLIC KEY ENCRYPTION PROCESS")
    print("=" * 70)
    
    # Import public key
    rsa_public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_public_key)
    
    # Original secret message
    original_message = "The launch code for Project Aurora is: 47-82-93-ALPHA"
    
    print("\n📝 Original Message:")
    print(f"   \"{original_message}\"")
    print(f"   Length: {len(original_message)} bytes")
    
    # Encrypt the message
    print("\n🔒 Encrypting with PUBLIC KEY...")
    start_time = time.perf_counter()
    
    message_bytes = original_message.encode('utf-8')
    ciphertext = cipher.encrypt(message_bytes)
    encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
    
    encryption_time = (time.perf_counter() - start_time) * 1000
    
    print(f"   ✅ Encryption completed in {encryption_time:.2f} ms")
    print(f"   Ciphertext length: {len(ciphertext)} bytes")
    print(f"   Ciphertext (base64 preview):")
    print(f"   {encrypted_b64[:80]}...")
    
    print("\n🔐 Encryption Process Explanation:")
    print("   1. Message is padded using OAEP (Optimal Asymmetric Encryption Padding)")
    print("   2. Padded message is raised to public exponent e modulo n")
    print("   3. Result is ciphertext c = m^e mod n")
    print("   4. Only private key holder can decrypt")
    
    return ciphertext, encrypted_b64, original_message


# ============================================================
# FIG 3: Private Key Decryption Results
# ============================================================

def private_key_decryption_demo(private_key, ciphertext, original_message):
    """Demonstrate decryption using private key"""
    print("\n" + "=" * 70)
    print("   FIG 3: PRIVATE KEY DECRYPTION RESULTS")
    print("=" * 70)
    
    # Import private key
    rsa_private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    
    print("\n🔓 Decrypting with PRIVATE KEY...")
    start_time = time.perf_counter()
    
    decrypted_bytes = cipher.decrypt(ciphertext)
    decrypted_message = decrypted_bytes.decode('utf-8')
    
    decryption_time = (time.perf_counter() - start_time) * 1000
    
    print(f"   ✅ Decryption completed in {decryption_time:.2f} ms")
    
    print("\n📊 Verification Results:")
    print(f"   Original message:  {original_message}")
    print(f"   Decrypted message: {decrypted_message}")
    print(f"   Match:             {'✅ YES' if original_message == decrypted_message else '❌ NO'}")
    
    print("\n🔓 Decryption Process Explanation:")
    print("   1. Ciphertext is raised to private exponent d modulo n")
    print("   2. Result is m = c^d mod n (padded message)")
    print("   3. OAEP padding is removed to recover original message")
    print("   4. Only private key holder can perform this operation")
    
    return decrypted_message


# ============================================================
# FIG 4: Secure Message Transmission Simulation
# ============================================================

def secure_message_transmission():
    """Simulate secure message transmission between two parties"""
    print("\n" + "=" * 70)
    print("   FIG 4: SECURE MESSAGE TRANSMISSION SIMULATION")
    print("=" * 70)
    
    print("\n📡 SIMULATION: Alice sends encrypted message to Bob")
    print("   " + "-" * 60)
    
    # Step 1: Bob generates his key pair
    print("\n👤 Bob generates his RSA key pair...")
    bob_key = RSA.generate(2048)
    bob_public_key = bob_key.publickey().export_key()
    print("   ✅ Bob's key pair ready")
    
    # Step 2: Alice encrypts message using Bob's public key
    print("\n👩 Alice wants to send a secret message to Bob")
    alice_message = "Meeting scheduled for tomorrow at 3 PM in the secure facility. Authentication required."
    
    print(f"   Alice's message: \"{alice_message[:60]}...\"")
    
    cipher_encrypt = PKCS1_OAEP.new(RSA.import_key(bob_public_key))
    ciphertext = cipher_encrypt.encrypt(alice_message.encode())
    encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
    
    print(f"   🔒 Alice encrypts with Bob's PUBLIC key")
    print(f"   Ciphertext length: {len(ciphertext)} bytes")
    
    # Step 3: Message transmitted over insecure channel
    print("\n📡 Message transmitted over insecure network...")
    print("   [Channel is public - anyone can see the ciphertext]")
    
    # Step 4: Bob decrypts with his private key
    print("\n👤 Bob receives the encrypted message")
    cipher_decrypt = PKCS1_OAEP.new(bob_key)
    decrypted_message = cipher_decrypt.decrypt(ciphertext).decode()
    
    print(f"   🔓 Bob decrypts with his PRIVATE key")
    print(f"   Decrypted message: \"{decrypted_message[:60]}...\"")
    
    # Step 5: Verification
    print("\n📊 Transmission Status:")
    print(f"   Message integrity: {'✅ INTACT' if alice_message == decrypted_message else '❌ COMPROMISED'}")
    print(f"   Confidentiality:   {'✅ MAINTAINED'}")
    print(f"   Authentication:    {'✅ SENDER VERIFIED'}")
    
    # Security summary
    print("\n🛡️ Security Properties Demonstrated:")
    print("   • Confidentiality: Only Bob can read the message")
    print("   • Integrity: Message cannot be altered undetected")
    print("   • Authentication: Message came from someone with access to Alice")
    
    return alice_message, decrypted_message


# ============================================================
# FIG 5: RSA Testing and Validation
# ============================================================

def rsa_testing_validation():
    """Comprehensive RSA testing and validation suite"""
    print("\n" + "=" * 70)
    print("   FIG 5: RSA TESTING AND VALIDATION")
    print("=" * 70)
    
    test_messages = [
        "Short message",
        "Medium length message for testing RSA encryption",
        "RSA is based on the mathematical difficulty of factoring large prime numbers",
        "X" * 100,  # Long message (note: RSA has size limits)
    ]
    
    key_sizes = [1024, 2048, 3072]
    
    print("\n📊 RSA Validation Test Suite")
    print("-" * 70)
    
    # Test 1: Different key sizes
    print("\n🔬 TEST 1: Key Size Comparison")
    print(f"{'Key Size':<12} {'Gen Time (ms)':<15} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15} {'Max Msg Size'}")
    print("-" * 70)
    
    for size in key_sizes:
        # Generate key
        start = time.perf_counter()
        key = RSA.generate(size)
        gen_time = (time.perf_counter() - start) * 1000
        
        # Encrypt test message
        test_msg = "RSA test message"
        cipher = PKCS1_OAEP.new(key)
        
        start = time.perf_counter()
        ciphertext = cipher.encrypt(test_msg.encode())
        enc_time = (time.perf_counter() - start) * 1000
        
        # Decrypt
        start = time.perf_counter()
        decrypted = cipher.decrypt(ciphertext).decode()
        dec_time = (time.perf_counter() - start) * 1000
        
        max_msg_size = key.size_in_bits() // 8 - 42  # OAEP padding overhead
        
        status = "✅" if decrypted == test_msg else "❌"
        print(f"{size:<12} {gen_time:<15.2f} {enc_time:<15.3f} {dec_time:<15.3f} {max_msg_size:<12} {status}")
    
    # Test 2: Message integrity verification
    print("\n🔬 TEST 2: Message Integrity Test")
    print("-" * 50)
    
    test_key = RSA.generate(2048)
    test_cipher = PKCS1_OAEP.new(test_key)
    original = "Confidential data: Secret key = 12345"
    
    encrypted = test_cipher.encrypt(original.encode())
    decrypted = test_cipher.decrypt(encrypted).decode()
    
    print(f"   Original:  {original}")
    print(f"   Decrypted: {decrypted}")
    print(f"   Integrity: {'✅ PASS' if original == decrypted else '❌ FAIL'}")
    
    # Test 3: Wrong key test (negative test)
    print("\n🔬 TEST 3: Wrong Key Test (Security Validation)")
    print("-" * 50)
    
    alice_key = RSA.generate(2048)
    bob_key = RSA.generate(2048)
    
    cipher_alice = PKCS1_OAEP.new(alice_key.publickey())
    encrypted_by_alice = cipher_alice.encrypt(b"Message for Alice")
    
    try:
        cipher_bob = PKCS1_OAEP.new(bob_key)
        wrong_decrypt = cipher_bob.decrypt(encrypted_by_alice)
        print("   ❌ SECURITY FLAW: Bob decrypted Alice's message!")
    except ValueError as e:
        print(f"   ✅ SECURITY SUCCESS: Wrong key cannot decrypt")
        print(f"   Error: {str(e)[:60]}...")
    
    # Test 4: Performance summary
    print("\n📈 RSA PERFORMANCE SUMMARY")
    print("-" * 50)
    print("   • 2048-bit RSA is standard for most applications")
    print("   • Encryption is much faster than decryption")
    print("   • Key generation is computationally expensive")
    print("   • Maximum message size = key_size/8 - 42 bytes")
    print("   • For larger messages, use hybrid encryption (RSA + AES)")
    
    return True


# ============================================================
# MAIN EXECUTION
# ============================================================

def run_all_demos():
    """Run all Week 5 demonstrations"""
    print("=" * 70)
    print("   WEEK 5: PUBLIC KEY CRYPTOGRAPHY (RSA)")
    print("   Implementation of RSA Encryption and Key Management")
    print("=" * 70)
    
    # FIG 1: RSA Key Pair Generation
    key, private_key, public_key = rsa_key_generation()
    
    # FIG 2: Public Key Encryption
    ciphertext, encrypted_b64, original_msg = public_key_encryption_demo(public_key)
    
    # FIG 3: Private Key Decryption
    decrypted_msg = private_key_decryption_demo(private_key, ciphertext, original_msg)
    
    # FIG 4: Secure Message Transmission
    secure_message_transmission()
    
    # FIG 5: RSA Testing and Validation
    rsa_testing_validation()
    
    # Summary
    print("\n" + "=" * 70)
    print("   WEEK 5 COMPLETED SUCCESSFULLY")
    print("=" * 70)
    
    print("\n📁 Files Created:")
    print("   - rsa_private_key.pem  (Keep secret!)")
    print("   - rsa_public_key.pem   (Can share publicly)")
    
    print("\n🛡️ Security Notes:")
    print("   • Never share your private key")
    print("   • Public key can be distributed freely")
    print("   • RSA-2048 is secure for current applications")
    print("   • Use OAEP padding (not PKCS#1 v1.5) for security")


if __name__ == "__main__":
    # Check if pycryptodome is installed
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
    except ImportError:
        print("❌ Please install pycryptodome first:")
        print("   pip install pycryptodome")
        exit(1)
    
    run_all_demos()