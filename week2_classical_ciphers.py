"""
Week 2: Classical Cryptography and Cipher Design
Implementation of Caesar Cipher and Vigenère Cipher
"""

import re

# ============================================================
# FIG 1: Caesar Cipher Implementation
# ============================================================

class CaesarCipher:
    """Classic shift cipher - shifts each letter by fixed amount"""
    
    def __init__(self, shift):
        self.shift = shift % 26
    
    def encrypt(self, text):
        """Encrypt text using Caesar shift"""
        result = []
        for char in text:
            if char.isupper():
                shifted = ord(char) + self.shift
                if shifted > ord('Z'):
                    shifted -= 26
                result.append(chr(shifted))
            elif char.islower():
                shifted = ord(char) + self.shift
                if shifted > ord('z'):
                    shifted -= 26
                result.append(chr(shifted))
            else:
                result.append(char)
        return ''.join(result)
    
    def decrypt(self, text):
        """Decrypt by shifting backward"""
        self.shift = -self.shift
        result = self.encrypt(text)
        self.shift = -self.shift
        return result


# ============================================================
# FIG 2: Vigenère Cipher Encryption Process
# ============================================================

class VigenereCipher:
    """Polyalphabetic cipher using keyword for shifting"""
    
    def __init__(self, keyword):
        self.keyword = keyword.upper()
        self.keyword_length = len(keyword)
    
    def _shift_char(self, char, key_char, encrypt=True):
        """Shift a single character based on key character"""
        if not char.isalpha():
            return char
        
        # Get base (A=65 for uppercase, a=97 for lowercase)
        base = ord('A') if char.isupper() else ord('a')
        char_num = ord(char) - base
        
        # Key shift value (0-25)
        key_shift = ord(key_char.upper()) - ord('A')
        
        if not encrypt:
            key_shift = -key_shift
        
        shifted = (char_num + key_shift) % 26
        return chr(base + shifted)
    
    def encrypt(self, text):
        """Encrypt text using Vigenère cipher"""
        result = []
        key_index = 0
        
        for char in text:
            if char.isalpha():
                key_char = self.keyword[key_index % self.keyword_length]
                result.append(self._shift_char(char, key_char, encrypt=True))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, text):
        """Decrypt text using Vigenère cipher"""
        result = []
        key_index = 0
        
        for char in text:
            if char.isalpha():
                key_char = self.keyword[key_index % self.keyword_length]
                result.append(self._shift_char(char, key_char, encrypt=False))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)


# ============================================================
# FIG 3 & 4: User Input Validation Interface + Encryption Output
# ============================================================

def validate_input(text, cipher_type="caesar"):
    """Validate user input for encryption"""
    errors = []
    
    if not text or not text.strip():
        errors.append("❌ Error: Input text cannot be empty")
    
    if cipher_type == "caesar" and len(text) < 3:
        errors.append("⚠️ Warning: Very short text may be easily cracked")
    
    # Check for non-ASCII characters
    if any(ord(char) > 127 for char in text):
        errors.append("⚠️ Warning: Non-ASCII characters detected")
    
    # Count special characters (will be preserved, not encrypted)
    special_count = sum(1 for char in text if not char.isalpha() and not char.isspace())
    if special_count > 0:
        errors.append(f"ℹ️ Info: {special_count} special character(s) will be preserved as-is")
    
    return errors


def display_menu():
    """Interactive menu for cipher testing"""
    print("\n" + "=" * 60)
    print("   CLASSICAL CRYPTOGRAPHY - ENCRYPTION/DECRYPTION TOOL")
    print("=" * 60)
    print("\nChoose an option:")
    print("  1. Caesar Cipher")
    print("  2. Vigenère Cipher")
    print("  3. Cipher Testing Suite (Fig 5)")
    print("  4. Exit")
    return input("\nEnter choice (1-4): ").strip()


# ============================================================
# FIG 5: Cipher Testing Results
# ============================================================

def run_cipher_tests():
    """Run comprehensive tests on both ciphers"""
    
    print("\n" + "=" * 70)
    print("   CIPHER TESTING RESULTS - SECURITY ANALYSIS")
    print("=" * 70)
    
    test_cases = [
        ("Short", "Hello"),
        ("With Spaces", "Secret Message Here"),
        ("Punctuation", "Top Secret! Don't share."),
        ("Numbers Mixed", "Meeting at 9am"),
        ("Mixed Case", "ATTACK at Dawn")
    ]
    
    # Test Caesar Cipher
    print("\n" + "─" * 70)
    print("📊 TEST 1: CAESAR CIPHER ANALYSIS")
    print("─" * 70)
    
    for name, plaintext in test_cases:
        caesar = CaesarCipher(shift=3)
        encrypted = caesar.encrypt(plaintext)
        decrypted = caesar.decrypt(encrypted)
        
        status = "✓ PASS" if decrypted == plaintext else "✗ FAIL"
        print(f"\n{status} | {name}:")
        print(f"   Original:  {plaintext}")
        print(f"   Encrypted: {encrypted}")
        print(f"   Decrypted: {decrypted}")
    
    # Test Vigenère Cipher
    print("\n" + "─" * 70)
    print("📊 TEST 2: VIGENÈRE CIPHER ANALYSIS")
    print("─" * 70)
    
    keyword = "CRYPTO"
    print(f"\nUsing Keyword: {keyword}")
    
    for name, plaintext in test_cases:
        vigenere = VigenereCipher(keyword)
        encrypted = vigenere.encrypt(plaintext)
        decrypted = vigenere.decrypt(encrypted)
        
        status = "✓ PASS" if decrypted == plaintext else "✗ FAIL"
        print(f"\n{status} | {name}:")
        print(f"   Original:  {plaintext}")
        print(f"   Encrypted: {encrypted}")
        print(f"   Decrypted: {decrypted}")
    
    # Security Comparison
    print("\n" + "─" * 70)
    print("📊 TEST 3: SECURITY COMPARISON")
    print("─" * 70)
    
    print("""
┌─────────────────┬────────────────────────┬─────────────────────────┐
│    Property     │     Caesar Cipher       │    Vigenère Cipher      │
├─────────────────┼────────────────────────┼─────────────────────────┤
│ Type            │ Monoalphabetic          │ Polyalphabetic          │
│ Key Space Size  │ 25 possible shifts      │ 26^L (L=key length)     │
│ Frequency Hiding│ Poor (patterns visible) │ Good (flattens distro)  │
│ Brute Force     │ Trivial (26 tries)      │ Impractical for long key│
│ Known Plaintext │ Easily broken           │ Key can be recovered    │
│ Best Attack     │ Brute force / frequency │ Kasiski / Index of Coin │
└─────────────────┴────────────────────────┴─────────────────────────┘
    """)
    
    return True


# ============================================================
# MAIN EXECUTION
# ============================================================

def interactive_mode():
    """Run interactive encryption tool"""
    while True:
        choice = display_menu()
        
        if choice == '4':
            print("\n👋 Exiting... Goodbye!")
            break
        
        elif choice == '1':
            print("\n" + "─" * 50)
            print("🔐 CAESAR CIPHER")
            print("─" * 50)
            
            text = input("Enter text to encrypt: ")
            validation = validate_input(text, "caesar")
            for msg in validation:
                print(msg)
            
            if validation and "Error" in validation[0]:
                continue
            
            try:
                shift = int(input("Enter shift value (1-25): "))
                if shift < 1 or shift > 25:
                    print("❌ Shift must be between 1 and 25")
                    continue
            except ValueError:
                print("❌ Please enter a valid number")
                continue
            
            caesar = CaesarCipher(shift)
            encrypted = caesar.encrypt(text)
            decrypted = caesar.decrypt(encrypted)
            
            print(f"\n📝 Original:  {text}")
            print(f"🔒 Encrypted: {encrypted}")
            print(f"🔓 Decrypted: {decrypted}")
        
        elif choice == '2':
            print("\n" + "─" * 50)
            print("🔐 VIGENÈRE CIPHER")
            print("─" * 50)
            
            text = input("Enter text to encrypt: ")
            validation = validate_input(text, "vigenere")
            for msg in validation:
                print(msg)
            
            keyword = input("Enter keyword (letters only): ").upper()
            if not keyword.isalpha():
                print("❌ Keyword must contain only letters")
                continue
            
            vigenere = VigenereCipher(keyword)
            encrypted = vigenere.encrypt(text)
            decrypted = vigenere.decrypt(encrypted)
            
            print(f"\n📝 Original:  {text}")
            print(f"🔑 Keyword:   {keyword}")
            print(f"🔒 Encrypted: {encrypted}")
            print(f"🔓 Decrypted: {decrypted}")
        
        elif choice == '3':
            run_cipher_tests()
        
        else:
            print("❌ Invalid choice. Please enter 1-4")

# ============================================================
# RUN THE PROGRAM
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("   WEEK 2: CLASSICAL CRYPTOGRAPHY")
    print("   Caesar Cipher + Vigenère Cipher")
    print("=" * 60)
    
    interactive_mode()