# Simple-Crypto-Web-App
Secure Vault: Store encrypted notes and files using a master password. Easily add, view, download, and delete your items. All data is encrypted with AES-GCM and saved locally for quick access and privacy.

# Simple Crypto Web App

A web-based cryptography toolkit that lets you encrypt/decrypt text, generate and analyze passwords, hash data, manage passwords, and securely store notes/files in a local encrypted vault.

## Features

- **Classical Ciphers:** Caesar, Vigenère, and Playfair encryption/decryption.
- **Password Tools:** Strength analyzer and generator with copy feature.
- **File Encryptor:** AES-256-CBC encryption/decryption for files.
- **Hashing Tool:** Generate and verify hashes (MD5, SHA1, SHA256, SHA512).
- **Password Manager:** Save passwords with hashing and salting; view stored passwords.
- **Vault / Safe:** Securely store notes and files with master password encryption; view, download, and delete items.

## Usage

1. Open `index.html` in your browser.
2. Navigate using the top menu.
3. Enter your master password for vault and password manager features.
4. Add notes/files, passwords, or encrypt/decrypt text as needed.
5. Data is stored locally in your browser (`localStorage`).

## Security Note

This is a **demo app** for learning purposes. For production, implement proper server-side storage, key management, and stronger encryption practices.

## License

MIT License
