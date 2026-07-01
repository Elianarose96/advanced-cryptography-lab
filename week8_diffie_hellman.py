"""
Week 8: Diffie-Hellman Key Exchange Implementation
Practical Task: Secure Key Exchange Protocol
"""

import random
import math

class DiffieHellman:
    """
    Diffie-Hellman Key Exchange Implementation
    Allows two parties to establish a shared secret over an insecure channel
    """
    
    def __init__(self, p, g):
        """
        Initialize with public parameters
        p: prime number (modulus)
        g: generator (primitive root modulo p)
        """
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
    def generate_private_key(self):
        """Generate a random private key (2 <= key < p-1)"""
        self.private_key = random.randint(2, self.p - 2)
        return self.private_key
    
    def set_private_key(self, key):
        """Set a specific private key (for demonstration)"""
        if 1 < key < self.p - 1:
            self.private_key = key
        else:
            raise ValueError(f"Private key must be between 2 and {self.p-2}")
    
    def compute_public_key(self):
        """Compute public key: A = g^a mod p"""
        if self.private_key is None:
            raise ValueError("Private key not set. Generate or set one first.")
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key):
        """
        Compute shared secret: S = B^a mod p
        where B is the other party's public key
        """
        if self.private_key is None:
            raise ValueError("Private key not set.")
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        return self.shared_secret
    
    def verify_shared_secret(self, other_secret):
        """Verify that both parties computed the same secret"""
        return self.shared_secret == other_secret


def is_prime(num):
    """Simple primality test for demonstration"""
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True


def is_primitive_root(g, p):
    """
    Check if g is a primitive root modulo p
    Simple check for demonstration
    """
    if g < 2 or g >= p:
        return False
    # Check if g generates all values 1..p-1
    values = set()
    for i in range(1, p):
        values.add(pow(g, i, p))
    return len(values) == p - 1


def diffie_hellman_demo():
    """Demonstrate Diffie-Hellman Key Exchange"""
    print("=" * 70)
    print("   DIFFIE-HELLMAN KEY EXCHANGE DEMONSTRATION")
    print("=" * 70)
    
    # Step 1: Public Parameters
    print("\n📋 Step 1: Public Parameters (Shared)")
    print("-" * 50)
    
    # Using small numbers for demonstration
    p = 23  # Prime number
    g = 5   # Generator
    
    print(f"   Prime (p):   {p} (modulus)")
    print(f"   Generator (g): {g} (primitive root)")
    print(f"   These values are PUBLIC and known to everyone")
    
    # Step 2: Alice's Private Key
    print("\n👩 Step 2: Alice's Key Generation")
    print("-" * 50)
    
    alice = DiffieHellman(p, g)
    alice_private = 6  # Using fixed for demonstration
    alice.set_private_key(alice_private)
    alice_public = alice.compute_public_key()
    
    print(f"   Alice's Private Key (a): {alice_private} (SECRET - only Alice knows)")
    print(f"   Alice's Public Key (A):  {alice_public} (PUBLIC - sent to Bob)")
    
    # Step 3: Bob's Private Key
    print("\n👨 Step 3: Bob's Key Generation")
    print("-" * 50)
    
    bob = DiffieHellman(p, g)
    bob_private = 15  # Using fixed for demonstration
    bob.set_private_key(bob_private)
    bob_public = bob.compute_public_key()
    
    print(f"   Bob's Private Key (b): {bob_private} (SECRET - only Bob knows)")
    print(f"   Bob's Public Key (B):  {bob_public} (PUBLIC - sent to Alice)")
    
    # Step 4: Exchange Public Keys
    print("\n📤 Step 4: Public Key Exchange")
    print("-" * 50)
    print(f"   Alice sends: A = {alice_public}")
    print(f"   Bob sends:   B = {bob_public}")
    print("   ⚠️ Public keys travel over an insecure channel")
    
    # Step 5: Compute Shared Secret
    print("\n🔐 Step 5: Computing Shared Secret")
    print("-" * 50)
    
    alice_secret = alice.compute_shared_secret(bob_public)
    bob_secret = bob.compute_shared_secret(alice_public)
    
    print(f"   Alice computes: S = B^a mod p = {bob_public}^{alice_private} mod {p} = {alice_secret}")
    print(f"   Bob computes:   S = A^b mod p = {alice_public}^{bob_private} mod {p} = {bob_secret}")
    
    # Step 6: Verification
    print("\n✅ Step 6: Verification")
    print("-" * 50)
    
    if alice_secret == bob_secret:
        print(f"   🎉 SUCCESS! Shared Secret: {alice_secret}")
        print("   ✅ Both parties computed the same key!")
        print("   🔑 This key can now be used for symmetric encryption")
    else:
        print("   ❌ ERROR: Shared secrets do not match!")
    
    # Mathematical Explanation
    print("\n📊 Mathematical Explanation:")
    print("-" * 50)
    print(f"   Alice: S = (g^b mod p)^a mod p = g^(ab) mod p")
    print(f"   Bob:   S = (g^a mod p)^b mod p = g^(ab) mod p")
    print(f"   Therefore: Alice's Secret = Bob's Secret = {alice_secret}")
    
    return alice_secret


def diffie_hellman_with_different_keys():
    """Demonstrate with random keys"""
    print("\n" + "=" * 70)
    print("   DIFFIE-HELLMAN WITH RANDOM KEYS")
    print("=" * 70)
    
    # Larger prime for better security
    p = 1009  # Prime
    g = 7     # Generator
    
    print(f"\n📋 Public Parameters: p={p}, g={g}")
    
    # Alice
    alice = DiffieHellman(p, g)
    alice.generate_private_key()
    alice_public = alice.compute_public_key()
    
    # Bob
    bob = DiffieHellman(p, g)
    bob.generate_private_key()
    bob_public = bob.compute_public_key()
    
    print(f"\n👩 Alice: Private={alice.private_key}, Public={alice_public}")
    print(f"👨 Bob:   Private={bob.private_key}, Public={bob_public}")
    
    # Compute secrets
    alice_secret = alice.compute_shared_secret(bob_public)
    bob_secret = bob.compute_shared_secret(alice_public)
    
    print(f"\n🔐 Alice's Secret: {alice_secret}")
    print(f"🔐 Bob's Secret:   {bob_secret}")
    
    if alice_secret == bob_secret:
        print(f"\n✅ Shared Secret: {alice_secret}")
    else:
        print("\n❌ Secrets do not match!")
    
    return alice_secret


def security_analysis():
    """Analyze Diffie-Hellman security"""
    print("\n" + "=" * 70)
    print("   DIFFIE-HELLMAN SECURITY ANALYSIS")
    print("=" * 70)
    
    print("\n🛡️ Security Strengths:")
    print("   ✅ No prior shared secret needed")
    print("   ✅ Private keys never transmitted")
    print("   ✅ Secure against passive eavesdropping")
    print("   ✅ Based on the Discrete Logarithm Problem (DLP)")
    print("   ✅ Forms foundation of TLS/SSL protocols")
    
    print("\n⚠️ Limitations:")
    print("   ❌ No authentication (vulnerable to MITM attacks)")
    print("   ❌ Does not prevent active attacks")
    print("   ❌ Requires large prime numbers for strong security")
    print("   ❌ Performance overhead for large parameters")
    
    print("\n📋 Mitigations:")
    print("   • Combine with digital signatures for authentication")
    print("   • Use authenticated Diffie-Hellman (e.g., TLS)")
    print("   • Use elliptic curve variants (ECDH) for better performance")
    
    print("\n📊 Recommended Parameters:")
    print("   • 2048-bit prime numbers (minimum)")
    print("   • 3072-bit or 4096-bit for high security")
    print("   • Use RFC 3526 standard groups")


# ============================================================
# MAIN EXECUTION
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("   WEEK 8: DIFFIE-HELLMAN KEY EXCHANGE")
    print("   Practical Implementation and Analysis")
    print("=" * 70)
    
    # Demonstration with fixed keys
    diffie_hellman_demo()
    
    # Demonstration with random keys
    diffie_hellman_with_different_keys()
    
    # Security Analysis
    security_analysis()
    
    print("\n" + "=" * 70)
    print("   PRACTICAL TASK COMPLETED")
    print("=" * 70)
    
    print("\n📋 Key Takeaways:")
    print("   • Diffie-Hellman enables secure key exchange")
    print("   • Security relies on Discrete Logarithm Problem")
    print("   • Used in HTTPS, SSH, VPNs")
    print("   • Must be combined with authentication for full security")