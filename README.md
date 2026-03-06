# 🔒 CipherVault — Text Encryption Tool

A CLI-based text encryption tool built in Python that supports three industry-standard encryption algorithms: **AES-256**, **DES**, and **RSA-2048**.

---

## 📋 Requirements

- Python 3.7+
- `cryptography` library

---

## ⚙️ Installation

1. Clone or download the project files.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

Run the tool from your terminal:

```bash
python3 cipher_vault.py
```

Navigate the menu by entering the number for your desired option and pressing Enter.

---

## 🔐 Algorithms

### AES-256-CBC
- **Type:** Symmetric
- **Key size:** 256-bit (derived from your password via SHA-256)
- **Mode:** CBC with a random IV
- **Best for:** Fast, secure encryption of any text length

### DES-CBC
- **Type:** Symmetric (legacy)
- **Key size:** 64-bit (derived from your password via MD5)
- **Mode:** CBC with a random IV
- **Note:** DES is considered weak by modern standards and is included for educational/research purposes only

### RSA-2048
- **Type:** Asymmetric (public-key)
- **Key size:** 2048-bit
- **Padding:** OAEP with SHA-256
- **Note:** Automatically generates a key pair on first use. Limited to ~190 bytes of plaintext per operation.

---

## 📌 Menu Options

| Option | Description |
|--------|-------------|
| `1` | AES-256 encrypt / decrypt |
| `2` | DES encrypt / decrypt |
| `3` | RSA-2048 encrypt / decrypt / show public key |
| `4` | Compare all algorithms on the same text |
| `0` | Exit |

---

## 📤 Output Format

All encrypted output is returned as a **Base64-encoded string** on a single line.

- For AES and DES, the random IV is embedded silently inside the Base64 output.
- For RSA, the ciphertext is the direct Base64-encoded encrypted bytes.

Example output:
```
✓ AES-256 Encrypted (Base64):
  dGhpcyBpcyBhIHRlc3Q6abc123xyz==
```

---

## ⚠️ Notes

- AES and DES require a **password** for both encryption and decryption. Use the same password or decryption will fail.
- RSA keys are **session-only** — they are not saved to disk. If you restart the program, a new key pair is generated and previously encrypted data cannot be decrypted.
- This tool is intended for **educational and research purposes**.

---

## 📁 Project Structure

```
cipher_vault.py       # Main application
requirements.txt      # Python dependencies
README.md             # This file
```