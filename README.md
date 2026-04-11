# 🔒 Ciphertext — Text Encryption Tool

```
╔══════════════════════════════════════════════════════╗
║       ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗      ║
║      ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗     ║
║      ██║     ██║██████╔╝███████║█████╗  ██████╔╝     ║
║      ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗     ║
║      ╚██████╗██║██║     ██║  ██║███████╗██║  ██║     ║
║       ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ║
║              CIPHERTEXT — Text Encryption Tool            ║
╚══════════════════════════════════════════════════════╝
```

A command-line text encryption tool supporting five industry-standard algorithms — with an interactive menu and direct CLI mode.

---

## Features

- **AES-256-CBC** — Fast, widely-supported symmetric encryption
- **AES-256-GCM** — Authenticated encryption; detects tampering
- **ChaCha20-Poly1305** — Modern AEAD cipher, fast on all hardware
- **Triple DES (3DES-CBC)** — Legacy algorithm for compatibility
- **RSA-2048** — Asymmetric / public-key encryption
- **Compare mode** — Encrypt the same text with all algorithms side by side
- **File export** — Save any result to a timestamped `.txt` file
- **Clean piped output** — ANSI color codes are suppressed automatically when output is redirected

---

## Security Design

| Feature | Detail |
|---|---|
| Key derivation | scrypt (`N=32768, r=8, p=1`) — deliberately slow to resist brute force |
| Salt | 16 random bytes prepended to every ciphertext |
| Per-algorithm keys | Each algorithm mixes in a unique context string so the same password never produces the same key across ciphers |
| 3DES sub-keys | Three genuinely distinct 8-byte keys derived from one scrypt call |
| RSA private key | Optionally passphrase-protected on disk using `BestAvailableEncryption` |
| Error messages | Distinguishes invalid Base64 input, truncated ciphertext, wrong password, and tampered ciphertext |

> **Note:** Because scrypt is intentionally slow, each encrypt/decrypt operation takes roughly 0.5–1 second. This is expected behaviour — it's the brute-force protection working.

---

## Requirements

- Python 3.8+
- [`cryptography`](https://pypi.org/project/cryptography/) library

Install the dependency:

```bash
pip install cryptography
```

---

## Usage

### Interactive menu mode

```bash
python3 ciphertext.py
```

Launches a full menu. Select an algorithm, then choose Encrypt or Decrypt and follow the prompts.

### CLI direct mode

**Encrypt:**
```bash
python3 ciphertext.py --algo aes --operation encrypt --text "hello world" --password "mypass"
```

**Decrypt:**
```bash
python3 ciphertext.py --algo aes --operation decrypt --text "BASE64HERE" --password "mypass"
```

**Save output to file:**
```bash
python3 ciphertext.py --algo chacha20 --operation encrypt --text "secret" --password "mypass" --output
```

**RSA (no password needed):**
```bash
python3 ciphertext.py --algo rsa --operation encrypt --text "hello"
python3 ciphertext.py --algo rsa --operation decrypt --text "BASE64HERE"
```

### CLI arguments

| Argument | Values | Description |
|---|---|---|
| `--algo` | `aes`, `aesgcm`, `chacha20`, `des`, `rsa` | Algorithm to use |
| `--operation` | `encrypt`, `decrypt` | Operation to perform |
| `--text` | any string | Text to encrypt or decrypt |
| `--password` | any string | Password (symmetric algorithms only) |
| `--output` | flag | Save result to a `.txt` file |

---

## Algorithms

### AES-256-CBC
Standard symmetric block cipher. Recommended for general-purpose encryption. Ciphertext format: `salt(16) + iv(16) + ciphertext`.

### AES-256-GCM
AES with Galois/Counter Mode — authenticated encryption. Detects any tampering with the ciphertext. Ciphertext format: `salt(16) + iv(12) + tag(16) + ciphertext`.

### ChaCha20-Poly1305
Modern authenticated cipher. Fast on devices without AES hardware acceleration. Ciphertext format: `salt(16) + nonce(12) + ciphertext+tag`.

### Triple DES (3DES-CBC)
Legacy algorithm included for compatibility. **Not recommended for new systems** — use AES instead. Three distinct 8-byte sub-keys are derived from a single scrypt call. Ciphertext format: `salt(16) + iv(8) + ciphertext`.

### RSA-2048
Asymmetric encryption using OAEP padding with SHA-256. A key pair is generated on first use and saved to disk. Maximum plaintext size is ~190 bytes — use AES for larger data and RSA to encrypt the AES key.

**RSA key files:**
- `rsa_private.pem` — Private key (passphrase-protected if you set one during generation)
- `rsa_public.pem` — Public key (safe to share)

> ⚠️ Regenerating the RSA key pair will make all previously encrypted RSA ciphertexts permanently unrecoverable.

---

## Output Files

When `--output` is passed (CLI) or you choose to save in the menu, Ciphertext writes a file named:

```
ciphertext_<algo>_<operation>_<YYYYMMDD_HHMMSS>.txt
```

Example: `ciphertext_aes_encrypt_20260310_142503.txt`

---

## Piping & Scripting

Color codes are automatically stripped when output is not a terminal, so piping works cleanly:

```bash
# Encrypt and capture result
ENCRYPTED=$(python3 ciphertext.py --algo aesgcm --operation encrypt --text "hello" --password "pass")

# Decrypt it back
python3 ciphertext.py --algo aesgcm --operation decrypt --text "$ENCRYPTED" --password "pass"
```

---

## Compatibility Note

Ciphertexts produced by the current version are **not compatible** with older versions of Ciphertext that used bare SHA-256 key derivation. The binary layout now includes a 16-byte scrypt salt prefix.

---

## License

MIT