
from engine.crypto_engine import VaultCrypt512

def main():
    print("=" * 40)
    print("       VAULTCRYPT-512 ENGINE")
    print("=" * 40)

    message = b"VaultCrypt-512 initial encryption test"
    password = "TestPassword2026!"

    encrypted = VaultCrypt512.encrypt(message, password)
    decrypted = VaultCrypt512.decrypt(encrypted, password)

    print("Encryption:", "SUCCESS")
    print("Decryption:", "SUCCESS" if decrypted == message else "FAILED")
    print("SHA-512:", VaultCrypt512.fingerprint(message))
    print("Encrypted size:", len(encrypted), "bytes")

if __name__ == "__main__":
    main()
