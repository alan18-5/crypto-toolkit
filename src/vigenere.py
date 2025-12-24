"""Vigenere cipher implementation."""

from string import ascii_uppercase, ascii_lowercase

def _keystream(key: str, length: int):
    # repeat key to needed length
    key2 = (key * ((length // len(key)) + 1))[:length]
    return key2

def encrypt(plaintext: str, key: str) -> str:
    key_stream = _keystream(key, len(plaintext))
    out = []
    ki = 0
    for c in plaintext:
        k = key_stream[ki] if ki < len(key_stream) else 'A'
        if c.isupper():
            shift = ord(k.upper()) - ord('A')
            out.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            ki += 1
        elif c.islower():
            shift = ord(k.lower()) - ord('a')
            out.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)

def decrypt(ciphertext: str, key: str) -> str:
    key_stream = _keystream(key, len(ciphertext))
    out = []
    ki = 0
    for c in ciphertext:
        k = key_stream[ki] if ki < len(key_stream) else 'A'
        if c.isupper():
            shift = ord(k.upper()) - ord('A')
            out.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
            ki += 1
        elif c.islower():
            shift = ord(k.lower()) - ord('a')
            out.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)
