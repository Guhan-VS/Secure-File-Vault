# Security Design – Secure File Vault

## 1. Overview

Secure File Vault is designed to protect sensitive files through authenticated encryption, password-based key derivation, integrity validation, and encrypted payload concealment using PNG steganography.

The security design focuses on confidentiality, integrity, controlled file operations, and reliable recovery.

## 2. Cryptographic Protection

### AES-256-GCM

The encryption engine uses AES-GCM authenticated encryption.

Its security objectives include:

- Confidentiality of encrypted file contents.
- Authentication of encrypted data.
- Detection of unauthorized modifications.
- Rejection of invalid authentication tags during decryption.

### Password-Based Key Derivation

Argon2 is used for password-based key derivation through the key management component.

This separates password handling from the encryption workflow and makes password-derived key generation more resistant to brute-force attacks.

## 3. Vault Container Security

Encrypted files are stored using a dedicated vault container format.

The container and validation components are responsible for handling encrypted data and checking relevant structural information.

The project includes:

- Container format handling.
- Container inspection.
- Security validation.
- File recovery functionality.

## 4. File Integrity and Safe Operations

The project incorporates several mechanisms to improve file handling reliability:

- Cryptographic authentication through AES-GCM.
- SHA-256 digest verification for embedded steganography payloads.
- Validation of steganography headers and payload lengths.
- Temporary-file handling.
- Atomic output publishing using hard-link operations.
- Source-file metadata snapshot checks during encryption workflows.

These mechanisms help detect corruption and reduce risks associated with incomplete output files and ordinary source-file replacement scenarios.

## 5. PNG Steganography

Secure File Vault supports hiding encrypted `.vlt` files inside PNG images using Least Significant Bit (LSB) encoding.

The process consists of:

1. Encrypting the original file.
2. Embedding the encrypted vault payload into a PNG image.
3. Extracting the encrypted payload from the PNG.
4. Recovering the `.vlt` file.
5. Decrypting the recovered file using the correct password.

The steganography component validates its header, payload length, and SHA-256 digest.

**Security distinction:** Steganography provides concealment, not encryption. The embedded file must already be encrypted. The header checksum is not a keyed authentication mechanism; authenticated encryption remains the cryptographic protection for vault contents.

## 6. Threat Considerations

| Threat | Security mechanism |
|---|---|
| Unauthorized file reading | AES-GCM encryption |
| Incorrect password | Authenticated decryption |
| Encrypted data modification | AES-GCM authentication |
| Embedded payload corruption | SHA-256 verification |
| Invalid steganography header | Header validation and checksum |
| Incomplete output files | Temporary files and atomic publishing |
| Ordinary source-file replacement | Metadata snapshot validation |

These mechanisms mitigate specific risks but do not guarantee protection against every attack.

## 7. Current Limitations

- PNG steganography does not provide additional encryption.
- The steganography header checksum is not a keyed MAC or digital signature.
- Metadata snapshot checks are not an absolute defense against a deliberately crafted replacement file.
- Security also depends on password strength and the security of the host operating system.
- The project has not undergone an independent professional security audit.

## 8. Security Testing

The project includes automated tests covering:

- Encryption and decryption.
- Invalid passwords.
- Container validation.
- Integrity checks.
- File recovery.
- Temporary-file cleanup.
- Steganography embedding and extraction.
- Corrupted payload detection.
- Integration between encryption, steganography, and recovery.

Run the tests using:

```bash
python -m pytest
```

## 9. Responsible Disclosure

If you identify a security vulnerability, report it privately to the project maintainer before publicly disclosing technical details.

## 10. Disclaimer

Secure File Vault is an educational and development project. Its security mechanisms should not be treated as independently certified or professionally audited security software.