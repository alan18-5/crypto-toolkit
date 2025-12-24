import random
from math import gcd

# ---------- small utils ----------
def _egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError('No modular inverse')
    return x % m

def is_probable_prime(n: int, k: int = 8) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_candidate(bits: int) -> int:
    # generate odd integer with high bit set
    candidate = random.getrandbits(bits)
    candidate |= (1 << bits - 1) | 1
    return candidate

def generate_prime(bits: int) -> int:
    while True:
        p = generate_prime_candidate(bits)
        if is_probable_prime(p):
            return p

# ---------- RSA functions ----------
def generate_keypair(bits: int = 1024):
    """Generate (n, e, d) with two primes of size ~bits/2."""
    if bits < 32:
        raise ValueError("bits should be >= 32 for demo")
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    # choose e
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}

def encrypt_int(m: int, pub_n: int, pub_e: int) -> int:
    return pow(m, pub_e, pub_n)

def decrypt_int(c: int, priv_n: int, priv_d: int) -> int:
    return pow(c, priv_d, priv_n)

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def int_to_bytes(i: int) -> bytes:
    # remove leading zero-length
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length or 1, 'big')

def encrypt_bytes(plaintext: bytes, pub_n: int, pub_e: int) -> bytes:
    m = int_from_bytes(plaintext)
    if m >= pub_n:
        raise ValueError("Plaintext too large for key size")
    c = encrypt_int(m, pub_n, pub_e)
    return int_to_bytes(c)

def decrypt_bytes(ciphertext: bytes, priv_n: int, priv_d: int) -> bytes:
    c = int_from_bytes(ciphertext)
    m = decrypt_int(c, priv_n, priv_d)
    return int_to_bytes(m)

def sign_bytes(plaintext: bytes, priv_n: int, priv_d: int) -> bytes:
    """Sign by hashing then RSA-signing the integer hash."""
    import hashlib
    h = hashlib.sha256(plaintext).digest()
    m = int_from_bytes(h)
    sig = pow(m, priv_d, priv_n)
    return int_to_bytes(sig)

def verify_bytes(plaintext: bytes, signature: bytes, pub_n: int, pub_e: int) -> bool:
    import hashlib
    h = hashlib.sha256(plaintext).digest()
    m = int_from_bytes(h)
    s = int_from_bytes(signature)
    recovered = pow(s, pub_e, pub_n)
    return recovered == m
