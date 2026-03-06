# 🔒 CipherVault — Text Encryption Tool

A CLI-based text encryption tool built in Python supporting five industry-standard encryption algorithms: **AES-256-CBC**, **AES-256-GCM**, **ChaCha20-Poly1305**, **DES**, and **RSA-2048**. Supports both an interactive menu and direct command-line usage.

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

### Interactive Mode

Run the tool and navigate through the menu:

```bash
python3 cipher_vault.py
```

### CLI Direct Mode

Encrypt or decrypt without entering the menu by passing arguments directly:

```bash
# AES-256-CBC encrypt
python3 cipher_vault.py --algo aes --operation encrypt --text "hello world" --password "mypass"

# AES-256-GCM encrypt
python3 cipher_vault.py --algo aesgcm --operation encrypt --text "hello world" --password "mypass"

# ChaCha20-Poly1305 encrypt
python3 cipher_vault.py --algo chacha20 --operation encrypt --text "hello world" --password "mypass"

# DES encrypt
python3 cipher_vault.py --algo des --operation encrypt --text "hello world" --password "mypass"

# RSA encrypt (no password needed)
python3 cipher_vault.py --algo rsa --operation encrypt --text "hello world"

# Decrypt (any symmetric algo)
python3 cipher_vault.py --algo aesgcm --operation decrypt --text "BASE64..." --password "mypass"

# Save output to file
python3 cipher_vault.py --algo chacha20 --operation encrypt --text "hello" --password "mypass" --output
```

### CLI Arguments

| Argument | Values | Description |
|---|---|---|
| `--algo` | `aes`, `aesgcm`, `chacha20`, `des`, `rsa` | Algorithm to use |
| `--operation` | `encrypt`, `decrypt` | Operation to perform |
| `--text` | any string | Text to encrypt or decrypt |
| `--password` | any string | Password (required for all except RSA) |
| `--output` | flag | Save result to a `.txt` file |

---

## 🔐 Algorithms

### AES-256-CBC
- **Type:** Symmetric
- **Key size:** 256-bit (derived from password via SHA-256)
- **Mode:** CBC with a random 16-byte IV
- **Best for:** Fast, secure encryption of any text length

### AES-256-GCM
- **Type:** Symmetric — Authenticated Encryption (AEAD)
- **Key size:** 256-bit (derived from password via SHA-256)
- **Mode:** GCM with a random 12-byte nonce + 16-byte authentication tag
- **Best for:** Encryption where tamper detection is required — decryption will fail if the ciphertext was modified

### ChaCha20-Poly1305
- **Type:** Symmetric — Authenticated Encryption (AEAD)
- **Key size:** 256-bit (derived from password via SHA-256)
- **Nonce:** 12 bytes (random)
- **Best for:** Modern, fast authenticated encryption — especially on devices without AES hardware acceleration

### DES-CBC
- **Type:** Symmetric (legacy)
- **Key size:** 64-bit (derived from password via MD5)
- **Mode:** CBC with a random 8-byte IV
- **Note:** DES is considered weak by modern standards and is included for educational/research purposes only

### RSA-2048
- **Type:** Asymmetric (public-key)
- **Key size:** 2048-bit
- **Padding:** OAEP with SHA-256
- **Note:** Limited to ~190 bytes of plaintext per operation. No password needed — uses a generated key pair.

---

## 📌 Interactive Menu Options

| Option | Description |
|---|---|
| `1` | AES-256-CBC — encrypt / decrypt |
| `2` | AES-256-GCM — encrypt / decrypt |
| `3` | ChaCha20-Poly1305 — encrypt / decrypt |
| `4` | DES — encrypt / decrypt |
| `5` | RSA-2048 — encrypt / decrypt / show public key / regenerate keys |
| `6` | Compare all algorithms on the same text |
| `0` | Exit |

---

## 🔑 RSA Key Persistence

On first use, RSA automatically generates a 2048-bit key pair and saves it to disk:

```
rsa_private.pem   ← private key (keep this safe)
rsa_public.pem    ← public key
```

On subsequent runs, these keys are loaded automatically so previously encrypted data can still be decrypted. A **Regenerate Key Pair** option is available in the RSA menu — note that regenerating keys will make any previously encrypted ciphertexts permanently unrecoverable.

---

## 💾 File Export

After every encrypt/decrypt operation in interactive mode, you will be prompted:

```
Save output to file? (y/n):
```

If confirmed, the result is saved as a timestamped `.txt` file:

```
ciphervault_aesgcm_encrypt_20260306_091500.txt
```

Each file includes the algorithm used, operation type, timestamp, and the output value. In CLI mode, add the `--output` flag to save automatically.

---

## 📤 Output Format

All encrypted output is a **Base64-encoded string** printed on a single line. IVs, nonces, and authentication tags are embedded silently inside the Base64 output and are not shown separately.

Example:
```
✓ AES-GCM Encrypted (Base64):
  hX9kL2mNqR7tVwYz3aBcDeFgHiJkLmNoPqRsTuVwXyZ=
```

---

## ⚠️ Notes

- AES-GCM and ChaCha20-Poly1305 are **authenticated** — decryption will fail if the ciphertext has been tampered with.
- AES-CBC and DES require the **same password** for encryption and decryption. A wrong password will cause decryption to fail.
- RSA keys are saved to disk and persist across sessions. Back up `rsa_private.pem` if you need to decrypt data later.
- This tool is intended for **educational and research purposes**.

---

## 📁 Project Structure

```
cipher_vault.py       # Main application
requirements.txt      # Python dependencies
rsa_private.pem       # RSA private key (auto-generated on first use)
rsa_public.pem        # RSA public key (auto-generated on first use)
README.md             # This file
```