# src/cli.py
from src import caesar, vigenere, hashing, rsa_simple, signature_demo

BANNER = r'''
=========================================
        🔐 CRYPTO TOOLKIT 🔐
=========================================
  Encrypt • Decrypt • Hash • Sign • Verify
=========================================
'''

def pause():
    input("\n[Press Enter to continue]")

# ---------- Caesar Menu ----------
def caesar_menu():
    print("\n--- Caesar Cipher ---")
    text = input("Enter text: ")
    shift = int(input("Enter shift value: "))
    choice = input("1) Encrypt\n2) Decrypt\nChoose: ")

    if choice == "1":
        print("Encrypted:", caesar.encrypt(text, shift))
    elif choice == "2":
        print("Decrypted:", caesar.decrypt(text, shift))
    else:
        print("Invalid choice")

    pause()

# ---------- Vigenere Menu ----------
def vigenere_menu():
    print("\n--- Vigenère Cipher ---")
    text = input("Enter text: ")
    key = input("Enter key: ")
    choice = input("1) Encrypt\n2) Decrypt\nChoose: ")

    if choice == "1":
        print("Encrypted:", vigenere.encrypt(text, key))
    elif choice == "2":
        print("Decrypted:", vigenere.decrypt(text, key))
    else:
        print("Invalid choice")

    pause()

# ---------- Hash Menu ----------
def hash_menu():
    print("\n--- SHA-256 Hashing ---")
    text = input("Enter text: ")
    print("SHA-256:", hashing.sha256_text(text))
    pause()

# ---------- RSA Menu ----------
def rsa_menu():
    print("\n--- RSA Toolkit ---")
    print("1) Generate Keys")
    print("2) Encrypt Message")
    print("3) Decrypt Message")
    print("4) Sign Message")
    print("5) Verify Signature")
    choice = input("Choose: ")

    if choice == "1":
        bits = int(input("Enter key size (1024 recommended): "))
        keys = rsa_simple.generate_keypair(bits)
        print("\nPUBLIC KEY")
        print("n =", keys["n"])
        print("e =", keys["e"])
        print("\nPRIVATE KEY")
        print("d =", keys["d"])

    elif choice == "2":
        text = input("Enter message: ")
        n = int(input("Enter public key n: "))
        e = int(input("Enter public key e: "))
        cipher = rsa_simple.encrypt_bytes(text.encode(), n, e)
        print("Cipher (hex):", cipher.hex())

    elif choice == "3":
        cipher_hex = input("Enter cipher hex: ")
        n = int(input("Enter private key n: "))
        d = int(input("Enter private key d: "))
        cipher = bytes.fromhex(cipher_hex)
        plain = rsa_simple.decrypt_bytes(cipher, n, d)
        print("Decrypted:", plain.decode(errors="ignore"))

    elif choice == "4":
        text = input("Enter message: ")
        n = int(input("Enter private key n: "))
        d = int(input("Enter private key d: "))
        sig = rsa_simple.sign_bytes(text.encode(), n, d)
        print("Signature (hex):", sig.hex())

    elif choice == "5":
        text = input("Enter message: ")
        sig_hex = input("Enter signature hex: ")
        n = int(input("Enter public key n: "))
        e = int(input("Enter public key e: "))
        sig = bytes.fromhex(sig_hex)
        ok = rsa_simple.verify_bytes(text.encode(), sig, n, e)
        print("Verification:", "PASS ✅" if ok else "FAIL ❌")

    else:
        print("Invalid choice")

    pause()

# ---------- Signature Demo ----------
def signature_demo_menu():
    print("\n--- Digital Signature Demo ---")
    msg = input("Enter message: ")
    bits = int(input("Enter key size (1024 recommended): "))
    signature_demo.demo_sign_verify(msg, bits)
    pause()

# ---------- MAIN MENU ----------
def main():
    while True:
        print(BANNER)
        print("1) Caesar Cipher")
        print("2) Vigenère Cipher")
        print("3) SHA-256 Hash")
        print("4) RSA Toolkit")
        print("5) Digital Signature Demo")
        print("6) Exit")

        choice = input("\nSelect option: ")

        if choice == "1":
            caesar_menu()
        elif choice == "2":
            vigenere_menu()
        elif choice == "3":
            hash_menu()
        elif choice == "4":
            rsa_menu()
        elif choice == "5":
            signature_demo_menu()
        elif choice == "6":
            print("\nExiting... Stay safe 🔐")
            break
        else:
            print("Invalid option")
            pause()

if __name__ == "__main__":
    main()
