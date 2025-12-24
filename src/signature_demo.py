"""Simple demo that signs & verifies a message using rsa_simple."""

from src import rsa_simple, hashing

def demo_sign_verify(message: str, keysize: int = 1024):
    print("[*] Generating keypair (this may take a few seconds)...")
    keys = rsa_simple.generate_keypair(bits=keysize)
    n = keys['n']; e = keys['e']; d = keys['d']
    print(f"[*] Key generated. n bitlen ~= {n.bit_length()} e={e}")

    msg_bytes = message.encode('utf-8')
    digest = hashing.sha256_text(message)
    print(f"[*] SHA-256 digest: {digest}")

    signature = rsa_simple.sign_bytes(msg_bytes, n, d)
    print(f"[*] Signature (hex, truncated): {signature.hex()[:64]}...")

    ok = rsa_simple.verify_bytes(msg_bytes, signature, n, e)
    print("[*] Verification:", "PASS" if ok else "FAIL")
    return ok, keys, signature
