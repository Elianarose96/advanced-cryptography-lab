"""
Week 6: Hashing and Password Security
Implementation of SHA-256, Password Hashing, and Authentication
"""

import hashlib
import os
import time
import secrets
from typing import Dict, Tuple

# ============================================================
# FIG 1: SHA-256 Hash Generation
# ============================================================

def sha256_demo():
    """Demonstrate SHA-256 hash generation"""
    print("\n" + "=" * 70)
    print("   FIG 1: SHA-256 HASH GENERATION")
    print("=" * 70)
    
    # Test messages
    test_messages = [
        "Hello World",
        "Hello World",  # Same message = same hash
        "Hello World!", # Different message = completely different hash
        "Cryptography is fascinating",
        "A" * 100       # Long message
    ]
    
    print("\n📝 SHA-256 Hash Demo (One-way Function)")
    print("-" * 60)
    
    for msg in test_messages:
        # Generate SHA-256 hash
        hash_obj = hashlib.sha256(msg.encode())
        hash_hex = hash_obj.hexdigest()
        hash_bytes = hash_obj.digest()
        
        print(f"\n📌 Input: \"{msg[:50]}{'...' if len(msg) > 50 else ''}\"")
        print(f"   Length: {len(msg)} bytes")
        print(f"   SHA-256 (hex): {hash_hex[:64]}")
        print(f"   Hash length: {len(hash_hex)} hex chars = 256 bits")
        print(f"   Hash (bytes): {hash_bytes[:8].hex()}...")
    
    # Show avalanche effect
    print("\n❄️ Avalanche Effect Demonstration:")
    print("-" * 40)
    msg1 = "Secret"
    msg2 = "Secret "  # One space added
    
    hash1 = hashlib.sha256(msg1.encode()).hexdigest()
    hash2 = hashlib.sha256(msg2.encode()).hexdigest()
    
    print(f"   Message 1: '{msg1}' -> {hash1[:32]}...")
    print(f"   Message 2: '{msg2}' -> {hash2[:32]}...")
    
    # Count differing bits
    diff_count = sum(1 for a, b in zip(hash1, hash2) if a != b)
    print(f"   Different hex chars: {diff_count}/64 ({diff_count/64*100:.1f}% different)")
    print("   ✅ Small input change → Completely different output")
    
    return hash1


# ============================================================
# FIG 2: Password Hashing System (With Salt)
# ============================================================

class PasswordHasher:
    """Secure password hashing with salt"""
    
    def __init__(self, algorithm='sha256'):
        self.algorithm = algorithm
    
    def hash_password(self, password: str, salt: bytes = None) -> Dict:
        """
        Hash password with random salt
        Returns: Dictionary with salt, hash, and algorithm
        """
        if salt is None:
            salt = os.urandom(32)  # 256-bit salt
        
        # Combine password and salt
        password_bytes = password.encode('utf-8')
        salted_password = salt + password_bytes
        
        # Hash the combination
        if self.algorithm == 'sha256':
            hash_obj = hashlib.sha256(salted_password)
        elif self.algorithm == 'sha512':
            hash_obj = hashlib.sha512(salted_password)
        else:
            hash_obj = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
        
        password_hash = hash_obj.hexdigest() if hasattr(hash_obj, 'hexdigest') else hash_obj.hex()
        
        return {
            'salt': salt.hex(),
            'hash': password_hash,
            'algorithm': self.algorithm
        }
    
    def verify_password(self, password: str, stored_salt_hex: str, stored_hash: str) -> bool:
        """Verify password against stored salt and hash"""
        salt = bytes.fromhex(stored_salt_hex)
        new_hash_data = self.hash_password(password, salt)
        return new_hash_data['hash'] == stored_hash


def password_hashing_demo():
    """Demonstrate secure password hashing with salt"""
    print("\n" + "=" * 70)
    print("   FIG 2: PASSWORD HASHING SYSTEM (WITH SALT)")
    print("=" * 70)
    
    hasher = PasswordHasher(algorithm='sha256')
    
    print("\n🔐 Why Salting is Important:")
    print("   • Same password → Different hashes (because of unique salt)")
    print("   • Prevents rainbow table attacks")
    print("   • Makes brute force much harder")
    
    # Hash same password multiple times
    password = "MySecretPassword123!"
    
    print(f"\n📝 Password: \"{password}\"")
    print("-" * 50)
    
    for i in range(3):
        result = hasher.hash_password(password)
        print(f"\n   Attempt {i+1}:")
        print(f"   Salt (hex):  {result['salt'][:32]}...")
        print(f"   Hash (hex):  {result['hash'][:32]}...")
        print(f"   Algorithm:   {result['algorithm']}")
    
    print("\n🔒 Security Features:")
    print("   ✅ Unique salt per password")
    print("   ✅ 256-bit salt (32 bytes)")
    print("   ✅ SHA-256 cryptographic hash")
    print("   ✅ Same password → Different hashes")
    
    return hasher


# ============================================================
# FIG 3: Login Authentication Workflow
# ============================================================

def login_authentication_demo():
    """Demonstrate complete login authentication workflow"""
    print("\n" + "=" * 70)
    print("   FIG 3: LOGIN AUTHENTICATION WORKFLOW")
    print("=" * 70)
    
    # Simulate user database (stored hashes)
    user_database = {}
    hasher = PasswordHasher()
    
    print("\n📋 STEP 1: USER REGISTRATION")
    print("-" * 50)
    
    # User creates account
    username = "alice_crypto"
    password = "SecurePass456!"
    
    print(f"   👤 Username: {username}")
    print(f"   🔑 Password: {password}")
    
    # Hash password with salt and store
    stored_data = hasher.hash_password(password)
    user_database[username] = {
        'salt': stored_data['salt'],
        'hash': stored_data['hash']
    }
    
    print(f"\n   💾 Stored in database (NEVER store plain password):")
    print(f"      Salt:  {stored_data['salt'][:32]}...")
    print(f"      Hash:  {stored_data['hash'][:32]}...")
    print(f"      ✅ Registration complete!")
    
    print("\n" + "-" * 50)
    print("📋 STEP 2: LOGIN ATTEMPT")
    print("-" * 50)
    
    # Login attempt 1: Correct password
    print(f"\n   🔐 Login attempt: Username='{username}', Password='{password}'")
    
    user_record = user_database.get(username)
    if user_record:
        is_valid = hasher.verify_password(password, user_record['salt'], user_record['hash'])
        print(f"   🔓 Result: {'✅ ACCESS GRANTED' if is_valid else '❌ ACCESS DENIED'}")
    
    # Login attempt 2: Wrong password
    wrong_password = "WrongPassword123"
    print(f"\n   🔐 Login attempt: Username='{username}', Password='{wrong_password}'")
    
    user_record = user_database.get(username)
    if user_record:
        is_valid = hasher.verify_password(wrong_password, user_record['salt'], user_record['hash'])
        print(f"   🔒 Result: {'✅ ACCESS GRANTED' if is_valid else '❌ ACCESS DENIED'}")
    
    print("\n📊 WORKFLOW SUMMARY:")
    print("   1. User enters username + password")
    print("   2. System retrieves stored salt + hash for that username")
    print("   3. System hashes entered password with stored salt")
    print("   4. System compares hashes (NOT plain text!)")
    print("   5. If match → Login successful")
    
    return user_database, hasher


# ============================================================
# FIG 4: Hash Verification Results
# ============================================================

def hash_verification_demo():
    """Demonstrate hash verification with multiple test cases"""
    print("\n" + "=" * 70)
    print("   FIG 4: HASH VERIFICATION RESULTS")
    print("=" * 70)
    
    hasher = PasswordHasher()
    
    test_cases = [
        ("correct_horse_battery", "correct_horse_battery", True),   # Correct
        ("correct_horse_battery", "correct_horse_batterY", False),  # Wrong case
        ("password123", "password123", True),                        # Simple pass
        ("password123", "password124", False),                       # One char different
        ("", "", True),                                              # Empty password
        ("LongPasswordWithSpecial!@#", "LongPasswordWithSpecial!@#", True)
    ]
    
    print("\n🔍 Hash Verification Test Suite")
    print("-" * 70)
    print(f"{'Stored Password':<25} {'Entered Password':<25} {'Match':<10} {'Result'}")
    print("-" * 70)
    
    results = []
    
    for stored_pw, entered_pw, should_match in test_cases:
        # Hash the stored password
        stored_data = hasher.hash_password(stored_pw)
        
        # Verify entered password
        is_match = hasher.verify_password(entered_pw, stored_data['salt'], stored_data['hash'])
        
        status = "✅ PASS" if (is_match == should_match) else "❌ FAIL"
        match_str = "Yes" if is_match else "No"
        
        print(f"{stored_pw:<25} {entered_pw:<25} {match_str:<10} {status}")
        results.append({'passed': is_match == should_match})
    
    print("-" * 70)
    
    # Security demonstration
    print("\n🛡️ Security Benefits Demonstrated:")
    print("   • Passwords never stored in plain text")
    print("   • Even with database breach, passwords remain secure")
    print("   • Verification works without knowing original password")
    print("   • One-way function prevents password recovery")
    
    passed_count = sum(1 for r in results if r['passed'])
    print(f"\n📊 Test Summary: {passed_count}/{len(test_cases)} tests passed")
    
    return results


# ============================================================
# FIG 5: Password Security Testing
# ============================================================

def password_security_testing():
    """Test and compare password strength and hashing methods"""
    print("\n" + "=" * 70)
    print("   FIG 5: PASSWORD SECURITY TESTING")
    print("=" * 70)
    
    # Test passwords with different strength levels
    test_passwords = [
        ("weak", "password", "❌ Very Weak - Common password"),
        ("weak", "123456", "❌ Very Weak - Sequential numbers"),
        ("medium", "MyDogSpot2024", "⚠️ Medium - Longer but predictable"),
        ("strong", "Tr0ub4dor&3", "✅ Strong - Mixed case + numbers + symbol"),
        ("very_strong", "CorrectHorseBatteryStaple!", "✅ Very Strong - Long passphrase")
    ]
    
    print("\n📊 Password Strength Analysis")
    print("-" * 70)
    
    for strength, password, comment in test_passwords:
        # Calculate entropy (simplified)
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            charset_size += 33
        
        entropy = len(password) * (charset_size.bit_length() - 1) if charset_size > 0 else 0
        
        # Hash the password
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        
        print(f"\n   Password: \"{password}\"")
        print(f"   Strength: {comment}")
        print(f"   Length: {len(password)} chars")
        print(f"   Estimated entropy: ~{entropy} bits")
        print(f"   SHA-256: {sha256_hash[:40]}...")
    
    # Hashing speed comparison
    print("\n⏱️ Hashing Speed Comparison")
    print("-" * 60)
    
    test_password = "SecurePassword123!"
    
    algorithms = [
        ('MD5', hashlib.md5),
        ('SHA-1', hashlib.sha1),
        ('SHA-256', hashlib.sha256),
        ('SHA-512', hashlib.sha512)
    ]
    
    print(f"\n{'Algorithm':<10} {'Time (ms)':<12} {'Hash Length':<15} {'Security Status'}")
    print("-" * 60)
    
    for name, algo in algorithms:
        start = time.perf_counter()
        for _ in range(1000):
            algo(test_password.encode()).hexdigest()
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        security = "❌ Broken" if name in ['MD5', 'SHA-1'] else "✅ Secure"
        hash_len = algo().digest_size * 8
        
        print(f"{name:<10} {elapsed_ms:<12.3f} {hash_len:<15} {security}")
    
    print("-" * 60)
    
    # Security recommendations
    print("\n🔒 PASSWORD SECURITY RECOMMENDATIONS:")
    print("   ✅ Use passwords with 12+ characters")
    print("   ✅ Mix uppercase, lowercase, numbers, and symbols")
    print("   ✅ Use unique passwords for each account")
    print("   ✅ Enable 2FA (Two-Factor Authentication)")
    print("   ❌ Never reuse passwords")
    print("   ❌ Avoid dictionary words or personal info")
    print("   ❌ Don't store passwords in plain text")
    
    # Rainbow table resistance
    print("\n🌈 Rainbow Table Resistance:")
    print("   Without salt:  Same password → Same hash (vulnerable)")
    print("   With salt:     Same password → Different hashes (secure)")
    
    return True


# ============================================================
# BONUS: PBKDF2 Key Derivation (Industry Standard)
# ============================================================

def pbkdf2_demo():
    """Demonstrate PBKDF2 for secure password storage"""
    print("\n" + "=" * 70)
    print("   BONUS: PBKDF2 - Industry Standard Password Hashing")
    print("=" * 70)
    
    password = "MySecurePassword"
    salt = os.urandom(16)
    
    print(f"\n📝 Password: {password}")
    print(f"🧂 Salt: {salt.hex()[:32]}...")
    
    print("\n🔬 PBKDF2 with Different Iterations:")
    print("-" * 60)
    print(f"{'Iterations':<12} {'Time (ms)':<12} {'Security Level'}")
    print("-" * 60)
    
    for iterations in [1000, 10000, 100000]:
        start = time.perf_counter()
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        security = "Low" if iterations < 10000 else "Medium" if iterations < 100000 else "High"
        print(f"{iterations:<12} {elapsed_ms:<12.3f} {security}")
    
    print("-" * 60)
    print("\n✅ PBKDF2 is recommended for password storage (used by: Bitcoin, LastPass, 1Password)")


# ============================================================
# MAIN EXECUTION
# ============================================================

def run_all_demos():
    """Run all Week 6 demonstrations"""
    print("=" * 70)
    print("   WEEK 6: HASHING AND PASSWORD SECURITY")
    print("   SHA-256 | Password Hashing | Authentication")
    print("=" * 70)
    
    # FIG 1: SHA-256 Hash Generation
    sha256_demo()
    
    # FIG 2: Password Hashing System
    password_hashing_demo()
    
    # FIG 3: Login Authentication Workflow
    login_authentication_demo()
    
    # FIG 4: Hash Verification Results
    hash_verification_demo()
    
    # FIG 5: Password Security Testing
    password_security_testing()
    
    # BONUS: PBKDF2 Demo
    pbkdf2_demo()
    
    print("\n" + "=" * 70)
    print("   WEEK 6 COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    run_all_demos()