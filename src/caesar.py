"""Simple Caesar cipher (shift)."""

from string import ascii_uppercase, ascii_lowercase

def encrypt(plaintext: str, shift: int) -> str:
    def _shift_char(c):
        if c in ascii_uppercase:
            return ascii_uppercase[(ascii_uppercase.index(c) + shift) % 26]
        if c in ascii_lowercase:
            return ascii_lowercase[(ascii_lowercase.index(c) + shift) % 26]
        return c
    return ''.join(_shift_char(c) for c in plaintext)

def decrypt(ciphertext: str, shift: int) -> str:
    return encrypt(ciphertext, -shift)
