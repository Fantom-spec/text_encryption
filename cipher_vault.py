"""
╔═══════════════════════════════════════════╗
║         CIPHERVAULT — Text Encryption     ║
║  AES-256 · AES-GCM · DES · RSA · ChaCha  ║
╚═══════════════════════════════════════════╝
"""

import os
import base64
import hashlib
import argparse
import sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
except ImportError:
    _TripleDES = algorithms.TripleDES
from cryptography.hazmat.primitives import padding as sym_padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ─── FIX 6: Only use ANSI colors when stdout is a real terminal ──────────────
_IS_TTY = sys.stdout.isatty()

def _c(code: str) -> str:
    """Return ANSI escape code only when writing to a terminal."""
    return code if _IS_TTY else ""

BANNER = f"""
{_c(chr(27)+'[36m')}╔══════════════════════════════════════════════════════╗
║       ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗       ║
║      ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗      ║
║      ██║     ██║██████╔╝███████║█████╗  ██████╔╝      ║
║      ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗      ║
║      ╚██████╗██║██║     ██║  ██║███████╗██║  ██║      ║
║       ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ║
║                  {_c(chr(27)+'[32m')}VAULT{_c(chr(27)+'[36m')} — Text Encryption Tool           ║
╚══════════════════════════════════════════════════════╝{_c(chr(27)+'[0m')}
"""

# ─── ANSI Colors (FIX 6: strip codes when not a TTY) ─────────────────────────
C = {
    "reset":   _c("\033[0m"),
    "cyan":    _c("\033[36m"),
    "green":   _c("\033[32m"),
    "orange":  _c("\033[33m"),
    "red":     _c("\033[31m"),
    "dim":     _c("\033[90m"),
    "bold":    _c("\033[1m"),
    "white":   _c("\033[97m"),
    "magenta": _c("\033[35m"),
    "purple":  _c("\033[34m"),
}

def cprint(color, text):
    print(f"{C[color]}{text}{C['reset']}")

def header(title, color="cyan"):
    line = "─" * 54
    print(f"\n{C[color]}┌{line}┐")
    print(f"│  {title:<52}│")
    print(f"└{line}┘{C['reset']}")

def display_result(label: str, value: str, color: str = "green"):
    print(f"\n  {C[color]}{C['bold']}{label}{C['reset']}")
    print(f"  {C['white']}{value}{C['reset']}")


# ─── FIX 1: Slow key derivation with scrypt + salt ───────────────────────────
# scrypt is deliberately CPU/memory-hard, making brute-force attacks expensive.
# A unique random salt is prepended to the ciphertext so each encryption is
# independent even when the same password is reused.
_SCRYPT_N  = 2**15   # CPU/memory cost (32 768 iterations)
_SCRYPT_R  = 8       # block size
_SCRYPT_P  = 1       # parallelisation factor
_SALT_LEN  = 16      # bytes

def _derive_key(password: str, salt: bytes, key_len: int = 32,
                context: bytes = b"") -> bytes:
    """
    Derive a key using scrypt.
    FIX 4: `context` is mixed in so different algorithms always produce
    different keys even when the same password + salt are used.
    """
    kdf = Scrypt(
        salt=salt + context,
        length=key_len,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# ─── FIX 5: Helpers to produce clearer decryption error messages ─────────────
def _decode_base64(token: str, field_name: str = "ciphertext") -> bytes:
    """Raise a descriptive ValueError if the input is not valid base64."""
    try:
        return base64.b64decode(token.encode())
    except Exception:
        raise ValueError(
            f"The {field_name} is not valid Base64 — "
            "make sure you copied the full encrypted string without spaces."
        )

def _check_min_len(data: bytes, min_len: int, description: str):
    """Raise a descriptive ValueError if decrypted bytes are too short."""
    if len(data) < min_len:
        raise ValueError(
            f"The {description} is too short to be valid — "
            "it may be truncated or corrupted."
        )


# ─── AES-256-CBC ─────────────────────────────────────────────────────────────
# Layout: salt(16) + iv(16) + ciphertext
class AESCipher:
    _CONTEXT = b"aes-cbc"   # FIX 4: unique per-algorithm context

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        salt   = os.urandom(_SALT_LEN)
        key    = _derive_key(password, salt, 32, AESCipher._CONTEXT)
        iv     = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc    = cipher.encryptor()
        ct     = enc.update(padded) + enc.finalize()
        return base64.b64encode(salt + iv + ct).decode()

    @staticmethod
    def decrypt(token: str, password: str) -> str:
        raw = _decode_base64(token)
        _check_min_len(raw, _SALT_LEN + 16 + 16, "AES-CBC ciphertext")
        salt, iv, ct = raw[:_SALT_LEN], raw[_SALT_LEN:_SALT_LEN+16], raw[_SALT_LEN+16:]
        key    = _derive_key(password, salt, 32, AESCipher._CONTEXT)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec    = cipher.decryptor()
        try:
            padded = dec.update(ct) + dec.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            return (unpadder.update(padded) + unpadder.finalize()).decode()
        except (ValueError, UnicodeDecodeError):
            # FIX 5: padding failure means wrong password, not corrupt input
            raise ValueError("Decryption failed — the password is incorrect.")


# ─── Triple-DES-CBC ──────────────────────────────────────────────────────────
# FIX 2: Generate three genuinely distinct 8-byte keys (total 24 bytes).
# Using `key * 3` made all three sub-keys identical, reducing security to
# single-DES — which is broken. Three distinct keys restore the full 3DES
# benefit.
# Layout: salt(16) + iv(8) + ciphertext
class DESCipher:
    _CONTEXT = b"3des-cbc"

    @staticmethod
    def _derive_3des_key(password: str, salt: bytes) -> bytes:
        """Return 24 bytes (three distinct 8-byte 3DES sub-keys)."""
        # Derive 24 bytes in one scrypt call, then split into three 8-byte keys.
        raw = _derive_key(password, salt, 24, DESCipher._CONTEXT)
        k1, k2, k3 = raw[:8], raw[8:16], raw[16:24]
        # Edge case: if k1 == k2 or k2 == k3, XOR with a fixed diversifier
        # so they are never accidentally equal.
        if k1 == k2:
            k2 = bytes(b ^ 0xFF for b in k2)
        if k2 == k3:
            k3 = bytes(b ^ 0xAA for b in k3)
        return k1 + k2 + k3

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        salt   = os.urandom(_SALT_LEN)
        key    = DESCipher._derive_3des_key(password, salt)
        iv     = os.urandom(8)
        padder = sym_padding.PKCS7(64).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(_TripleDES(key), modes.CBC(iv), backend=default_backend())
        enc    = cipher.encryptor()
        ct     = enc.update(padded) + enc.finalize()
        return base64.b64encode(salt + iv + ct).decode()

    @staticmethod
    def decrypt(token: str, password: str) -> str:
        raw = _decode_base64(token)
        _check_min_len(raw, _SALT_LEN + 8 + 8, "3DES ciphertext")
        salt, iv, ct = raw[:_SALT_LEN], raw[_SALT_LEN:_SALT_LEN+8], raw[_SALT_LEN+8:]
        key    = DESCipher._derive_3des_key(password, salt)
        cipher = Cipher(_TripleDES(key), modes.CBC(iv), backend=default_backend())
        dec    = cipher.decryptor()
        try:
            padded = dec.update(ct) + dec.finalize()
            unpadder = sym_padding.PKCS7(64).unpadder()
            return (unpadder.update(padded) + unpadder.finalize()).decode()
        except (ValueError, UnicodeDecodeError):
            raise ValueError("Decryption failed — the password is incorrect.")


# ─── AES-256-GCM ─────────────────────────────────────────────────────────────
# Layout: salt(16) + iv(12) + tag(16) + ciphertext
class AESGCMCipher:
    _CONTEXT = b"aes-gcm"   # FIX 4

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        salt   = os.urandom(_SALT_LEN)
        key    = _derive_key(password, salt, 32, AESGCMCipher._CONTEXT)
        iv     = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        enc    = cipher.encryptor()
        ct     = enc.update(plaintext.encode()) + enc.finalize()
        tag    = enc.tag
        return base64.b64encode(salt + iv + tag + ct).decode()

    @staticmethod
    def decrypt(token: str, password: str) -> str:
        raw = _decode_base64(token)
        _check_min_len(raw, _SALT_LEN + 12 + 16 + 1, "AES-GCM ciphertext")
        salt = raw[:_SALT_LEN]
        iv   = raw[_SALT_LEN:_SALT_LEN+12]
        tag  = raw[_SALT_LEN+12:_SALT_LEN+28]
        ct   = raw[_SALT_LEN+28:]
        key  = _derive_key(password, salt, 32, AESGCMCipher._CONTEXT)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        dec  = cipher.decryptor()
        try:
            return (dec.update(ct) + dec.finalize()).decode()
        except InvalidTag:
            # FIX 5: GCM tag mismatch = wrong password or tampered ciphertext
            raise ValueError(
                "Decryption failed — the password is incorrect or the "
                "ciphertext has been tampered with."
            )


# ─── ChaCha20-Poly1305 ───────────────────────────────────────────────────────
# Layout: salt(16) + nonce(12) + ciphertext+tag
class ChaCha20Cipher:
    _CONTEXT = b"chacha20-poly1305"   # FIX 4

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        salt   = os.urandom(_SALT_LEN)
        key    = _derive_key(password, salt, 32, ChaCha20Cipher._CONTEXT)
        nonce  = os.urandom(12)
        chacha = ChaCha20Poly1305(key)
        ct     = chacha.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(salt + nonce + ct).decode()

    @staticmethod
    def decrypt(token: str, password: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        raw   = _decode_base64(token)
        _check_min_len(raw, _SALT_LEN + 12 + 16 + 1, "ChaCha20 ciphertext")
        salt  = raw[:_SALT_LEN]
        nonce = raw[_SALT_LEN:_SALT_LEN+12]
        ct    = raw[_SALT_LEN+12:]
        key   = _derive_key(password, salt, 32, ChaCha20Cipher._CONTEXT)
        chacha = ChaCha20Poly1305(key)
        try:
            return chacha.decrypt(nonce, ct, None).decode()
        except InvalidTag:
            # FIX 5: Poly1305 tag failure = wrong password or tampered ciphertext
            raise ValueError(
                "Decryption failed — the password is incorrect or the "
                "ciphertext has been tampered with."
            )


# ─── RSA-2048 ────────────────────────────────────────────────────────────────
RSA_PRIVATE_KEY_FILE = "rsa_private.pem"
RSA_PUBLIC_KEY_FILE  = "rsa_public.pem"

class RSACipher:
    _private_key = None
    _public_key  = None

    @classmethod
    def generate_keys(cls):
        cprint("dim", "  ⟳  Generating RSA-2048 key pair...")
        cls._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        cls._public_key = cls._private_key.public_key()
        cls._save_keys()
        cprint("green", f"  ✓  Key pair saved to {RSA_PRIVATE_KEY_FILE} and {RSA_PUBLIC_KEY_FILE}")

    @classmethod
    def _save_keys(cls):
        # FIX 3: Prompt for a passphrase and encrypt the private key on disk.
        # The file is useless to anyone who steals it without the passphrase.
        passphrase = cls._prompt_passphrase()
        encryption = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        )
        with open(RSA_PRIVATE_KEY_FILE, "wb") as f:
            f.write(cls._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                encryption
            ))
        with open(RSA_PUBLIC_KEY_FILE, "wb") as f:
            f.write(cls._public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    @staticmethod
    def _prompt_passphrase() -> bytes | None:
        """Ask the user for an optional passphrase to protect the private key."""
        import getpass
        cprint("dim", "  Enter a passphrase to protect the private key (leave blank = no protection):")
        p1 = getpass.getpass(f"  {C['dim']}Passphrase        : {C['reset']}")
        if not p1:
            cprint("orange", "  ⚠  Private key will be saved WITHOUT passphrase protection.")
            return None
        p2 = getpass.getpass(f"  {C['dim']}Confirm passphrase: {C['reset']}")
        if p1 != p2:
            cprint("red", "  ✗  Passphrases did not match — saving without protection.")
            return None
        return p1.encode()

    @classmethod
    def load_keys(cls) -> bool:
        if Path(RSA_PRIVATE_KEY_FILE).exists() and Path(RSA_PUBLIC_KEY_FILE).exists():
            import getpass
            try:
                with open(RSA_PRIVATE_KEY_FILE, "rb") as f:
                    pem_data = f.read()
                # Try loading without a password first (unprotected key)
                try:
                    cls._private_key = serialization.load_pem_private_key(
                        pem_data, password=None, backend=default_backend()
                    )
                except TypeError:
                    # Key is encrypted — prompt for passphrase
                    passphrase = getpass.getpass(
                        f"  {C['dim']}RSA private key passphrase: {C['reset']}"
                    )
                    cls._private_key = serialization.load_pem_private_key(
                        pem_data, password=passphrase.encode(), backend=default_backend()
                    )
                with open(RSA_PUBLIC_KEY_FILE, "rb") as f:
                    cls._public_key = serialization.load_pem_public_key(
                        f.read(), backend=default_backend()
                    )
                cprint("dim", "  ✓  RSA keys loaded from disk.")
                return True
            except (ValueError, TypeError):
                cprint("red", "  ✗  Wrong passphrase for RSA private key.")
                return False
        return False

    @classmethod
    def ensure_keys(cls):
        if cls._private_key is None:
            if not cls.load_keys():
                cls.generate_keys()

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        cls.ensure_keys()
        ct = cls._public_key.encrypt(
            plaintext.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ct).decode()

    @classmethod
    def decrypt(cls, token: str) -> str:
        cls.ensure_keys()
        # FIX 5: distinguish bad base64 from bad key/ciphertext
        ct = _decode_base64(token)
        try:
            return cls._private_key.decrypt(
                ct,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
        except ValueError:
            raise ValueError(
                "RSA decryption failed — the ciphertext may be corrupted, "
                "or it was encrypted with a different public key."
            )

    @classmethod
    def export_public_key(cls) -> str:
        cls.ensure_keys()
        return cls._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    @classmethod
    def regenerate_keys(cls):
        cprint("orange", "  ⚠  This will overwrite existing keys. Old ciphertexts will be unrecoverable.")
        confirm = input(f"  {C['dim']}Type YES to confirm: {C['reset']}").strip()
        if confirm == "YES":
            cls._private_key = None
            cls._public_key  = None
            cls.generate_keys()
        else:
            cprint("dim", "  Cancelled.")


# ─── File Export ─────────────────────────────────────────────
def save_to_file(content: str, algo: str, operation: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"ciphervault_{algo.lower()}_{operation}_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write(f"CipherVault Output\n")
        f.write(f"Algorithm : {algo}\n")
        f.write(f"Operation : {operation}\n")
        f.write(f"Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'─' * 40}\n")
        f.write(content + "\n")
    cprint("green", f"  ✓  Saved to {filename}")


def prompt_save(content: str, algo: str, operation: str):
    choice = input(f"\n  {C['dim']}Save output to file? (y/n): {C['reset']}").strip().lower()
    if choice == "y":
        save_to_file(content, algo, operation)


# ─── CLI Direct Mode ─────────────────────────────────────────
def run_cli(args):
    algo = args.algo.upper()
    op   = args.operation.lower()

    try:
        if algo == "AES":
            if not args.password:
                print("Error: --password required for AES."); sys.exit(1)
            result = AESCipher.encrypt(args.text, args.password) if op == "encrypt" else AESCipher.decrypt(args.text, args.password)

        elif algo == "DES":
            if not args.password:
                print("Error: --password required for DES."); sys.exit(1)
            result = DESCipher.encrypt(args.text, args.password) if op == "encrypt" else DESCipher.decrypt(args.text, args.password)

        elif algo == "AESGCM":
            if not args.password:
                print("Error: --password required for AES-GCM."); sys.exit(1)
            result = AESGCMCipher.encrypt(args.text, args.password) if op == "encrypt" else AESGCMCipher.decrypt(args.text, args.password)

        elif algo == "CHACHA20":
            if not args.password:
                print("Error: --password required for ChaCha20."); sys.exit(1)
            result = ChaCha20Cipher.encrypt(args.text, args.password) if op == "encrypt" else ChaCha20Cipher.decrypt(args.text, args.password)

        elif algo == "RSA":
            result = RSACipher.encrypt(args.text) if op == "encrypt" else RSACipher.decrypt(args.text)

        else:
            print(f"Unknown algorithm: {algo}"); sys.exit(1)

        print(result)

        if args.output:
            save_to_file(result, algo, op)

    except Exception as e:
        print(f"Error: {e}"); sys.exit(1)


# ─── Interactive Menu Handlers ────────────────────────────────
def run_aes():
    choice = action_menu("AES-256-CBC")
    if choice == "1":
        text = input(f"\n  {C['dim']}Plaintext : {C['reset']}")
        pwd  = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            token = AESCipher.encrypt(text, pwd)
            display_result("✓ AES-256 Encrypted (Base64):", token, "cyan")
            prompt_save(token, "AES", "encrypt")
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        pwd   = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            plain = AESCipher.decrypt(token, pwd)
            display_result("✓ AES-256 Decrypted:", plain, "green")
            prompt_save(plain, "AES", "decrypt")
        except Exception as e:
            cprint("red", f"  ✗ {e}")


def run_des():
    choice = action_menu("3DES (CBC)")
    if choice == "1":
        text = input(f"\n  {C['dim']}Plaintext : {C['reset']}")
        pwd  = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            token = DESCipher.encrypt(text, pwd)
            display_result("✓ 3DES Encrypted (Base64):", token, "orange")
            prompt_save(token, "3DES", "encrypt")
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        pwd   = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            plain = DESCipher.decrypt(token, pwd)
            display_result("✓ 3DES Decrypted:", plain, "green")
            prompt_save(plain, "3DES", "decrypt")
        except Exception as e:
            cprint("red", f"  ✗ {e}")


def run_rsa():
    choice = action_menu("RSA-2048")
    if choice == "1":
        text = input(f"\n  {C['dim']}Plaintext : {C['reset']}")
        if len(text.encode()) > 190:
            cprint("red", "  ✗ RSA-2048/OAEP supports up to ~190 bytes. Use AES for larger data.")
            return
        try:
            token = RSACipher.encrypt(text)
            display_result("✓ RSA-2048 Encrypted (Base64):", token, "green")
            prompt_save(token, "RSA", "encrypt")
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        try:
            plain = RSACipher.decrypt(token)
            display_result("✓ RSA-2048 Decrypted:", plain, "green")
            prompt_save(plain, "RSA", "decrypt")
        except Exception as e:
            cprint("red", f"  ✗ {e}")

    elif choice == "3":
        header("RSA PUBLIC KEY", "green")
        print(f"{C['dim']}{RSACipher.export_public_key()}{C['reset']}")

    elif choice == "4":
        RSACipher.regenerate_keys()


def run_aesgcm():
    choice = action_menu("AES-256-GCM")
    if choice == "1":
        text = input(f"\n  {C['dim']}Plaintext : {C['reset']}")
        pwd  = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            token = AESGCMCipher.encrypt(text, pwd)
            display_result("✓ AES-GCM Encrypted (Base64):", token, "magenta")
            prompt_save(token, "AES-GCM", "encrypt")
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        pwd   = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            plain = AESGCMCipher.decrypt(token, pwd)
            display_result("✓ AES-GCM Decrypted:", plain, "green")
            prompt_save(plain, "AES-GCM", "decrypt")
        except Exception as e:
            cprint("red", f"  ✗ {e}")


def run_chacha20():
    choice = action_menu("ChaCha20-Poly1305")
    if choice == "1":
        text = input(f"\n  {C['dim']}Plaintext : {C['reset']}")
        pwd  = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            token = ChaCha20Cipher.encrypt(text, pwd)
            display_result("✓ ChaCha20-Poly1305 Encrypted (Base64):", token, "purple")
            prompt_save(token, "ChaCha20", "encrypt")
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        pwd   = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            plain = ChaCha20Cipher.decrypt(token, pwd)
            display_result("✓ ChaCha20-Poly1305 Decrypted:", plain, "green")
            prompt_save(plain, "ChaCha20", "decrypt")
        except Exception as e:
            cprint("red", f"  ✗ {e}")


def run_compare():
    header("COMPARE ALL ALGORITHMS")
    text = input(f"  {C['dim']}Enter text to encrypt     : {C['reset']}")
    pwd  = input(f"  {C['dim']}Password (all except RSA) : {C['reset']}")

    if len(text.encode()) > 190:
        cprint("orange", "  ⚠  Text too long for RSA — RSA result will be skipped.")

    print(f"\n  {C['dim']}{'─'*54}{C['reset']}")

    for label, fn, color in [
        ("[AES-256-CBC]  ", lambda: AESCipher.encrypt(text, pwd),      "cyan"),
        ("[AES-256-GCM]  ", lambda: AESGCMCipher.encrypt(text, pwd),   "magenta"),
        ("[ChaCha20]     ", lambda: ChaCha20Cipher.encrypt(text, pwd),  "purple"),
        ("[3DES]         ", lambda: DESCipher.encrypt(text, pwd),       "orange"),
    ]:
        try:
            ct = fn()
            display_result(f"{label}{len(ct)} chars", ct[:64] + ("…" if len(ct) > 64 else ""), color)
        except Exception as e:
            cprint("red", f"  {label.strip()} Error: {e}")

    if len(text.encode()) <= 190:
        try:
            rsa_ct = RSACipher.encrypt(text)
            display_result(f"[RSA-2048]     {len(rsa_ct)} chars", rsa_ct[:64] + ("…" if len(rsa_ct) > 64 else ""), "green")
        except Exception as e:
            cprint("red", f"  RSA Error: {e}")

    print(f"\n  {C['dim']}{'─'*54}")
    cprint("dim", "  AES-GCM and ChaCha20 are authenticated — they detect tampering.")
    cprint("dim", "  RSA produces the largest ciphertext; AES-CBC is fastest for bulk data.")


def algo_menu():
    header("SELECT ALGORITHM")
    print(f"  {C['cyan']}[1]{C['reset']} AES-256-CBC  — Advanced Encryption Standard {C['dim']}(recommended){C['reset']}")
    print(f"  {C['magenta']}[2]{C['reset']} AES-256-GCM  — AES with Authenticated Encryption {C['dim']}(tamper-proof){C['reset']}")
    print(f"  {C['purple']}[3]{C['reset']} ChaCha20     — Modern AEAD Cipher {C['dim']}(fast & secure){C['reset']}")
    print(f"  {C['orange']}[4]{C['reset']} 3DES         — Triple DES {C['dim']}(legacy){C['reset']}")
    print(f"  {C['green']}[5]{C['reset']} RSA-2048     — Asymmetric / Public-Key Encryption")
    print(f"  {C['dim']}[6]{C['reset']} Compare All Algorithms on Same Text")
    print(f"  {C['red']}[0]{C['reset']} Exit")
    return input(f"\n  {C['dim']}>{C['reset']} ").strip()

def action_menu(algo: str):
    header(f"ACTION — {algo}")
    print(f"  {C['cyan']}[1]{C['reset']} Encrypt")
    print(f"  {C['orange']}[2]{C['reset']} Decrypt")
    if algo == "RSA-2048":
        print(f"  {C['green']}[3]{C['reset']} Show Public Key")
        print(f"  {C['orange']}[4]{C['reset']} Regenerate Key Pair")
    print(f"  {C['dim']}[0]{C['reset']} Back")
    return input(f"\n  {C['dim']}>{C['reset']} ").strip()


# ─── Entry Point ─────────────────────────────────────────────
def build_parser():
    parser = argparse.ArgumentParser(
        prog="cipher_vault",
        description="CipherVault — Encrypt/decrypt text using AES-256-CBC, AES-256-GCM, ChaCha20-Poly1305, 3DES, or RSA-2048.",
        epilog="""
Examples:
  python3 cipher_vault.py --algo aes      --operation encrypt --text "hello" --password "mypass"
  python3 cipher_vault.py --algo aesgcm   --operation encrypt --text "hello" --password "mypass"
  python3 cipher_vault.py --algo chacha20 --operation encrypt --text "hello" --password "mypass"
  python3 cipher_vault.py --algo rsa      --operation encrypt --text "hello"
  python3 cipher_vault.py --algo aes      --operation decrypt --text "BASE64..." --password "mypass" --output
        """
    )
    parser.add_argument("--algo",      choices=["aes", "aesgcm", "chacha20", "des", "rsa"], help="Algorithm to use")
    parser.add_argument("--operation", choices=["encrypt", "decrypt"], help="Operation to perform")
    parser.add_argument("--text",      help="Text to encrypt or decrypt")
    parser.add_argument("--password",  help="Password for symmetric algorithms")
    parser.add_argument("--output",    action="store_true", help="Save result to a .txt file")
    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # CLI direct mode
    if args.algo and args.operation and args.text:
        run_cli(args)
        return

    # Interactive menu mode
    print(BANNER)
    cprint("dim", "  Secure text encryption using industry-standard algorithms.")

    rsa_status = "keys found on disk" if (
        Path(RSA_PRIVATE_KEY_FILE).exists() and Path(RSA_PUBLIC_KEY_FILE).exists()
    ) else "will be generated on first use"
    cprint("dim", f"  RSA: {rsa_status}\n")

    while True:
        choice = algo_menu()
        if   choice == "1": run_aes()
        elif choice == "2": run_aesgcm()
        elif choice == "3": run_chacha20()
        elif choice == "4": run_des()
        elif choice == "5": run_rsa()
        elif choice == "6": run_compare()
        elif choice == "0":
            cprint("cyan", "\n  🔒 Session closed. Stay secure.\n")
            break
        else:
            cprint("red", "  Invalid choice. Try again.")


if __name__ == "__main__":
    main()