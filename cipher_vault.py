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
from cryptography.hazmat.backends import default_backend

BANNER = """
\033[36m╔══════════════════════════════════════════════════════╗
║       ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗       ║
║      ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗      ║
║      ██║     ██║██████╔╝███████║█████╗  ██████╔╝      ║
║      ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗      ║
║      ╚██████╗██║██║     ██║  ██║███████╗██║  ██║      ║
║       ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ║
║                  \033[32mVAULT\033[36m — Text Encryption Tool           ║
╚══════════════════════════════════════════════════════╝\033[0m
"""

# ─── ANSI Colors ─────────────────────────────────────────────
C = {
    "reset":   "\033[0m",
    "cyan":    "\033[36m",
    "green":   "\033[32m",
    "orange":  "\033[33m",
    "red":     "\033[31m",
    "dim":     "\033[90m",
    "bold":    "\033[1m",
    "white":   "\033[97m",
    "magenta": "\033[35m",
    "purple":  "\033[34m",
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


# ─── AES-256-CBC ─────────────────────────────────────────────
class AESCipher:
    @staticmethod
    def _derive_key(password: str) -> bytes:
        return hashlib.sha256(password.encode()).digest()

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        key = AESCipher._derive_key(password)
        iv  = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct  = enc.update(padded) + enc.finalize()
        return base64.b64encode(iv + ct).decode()

    @staticmethod
    def decrypt(token: str, password: str) -> str:
        raw = base64.b64decode(token.encode())
        key, iv, ct = AESCipher._derive_key(password), raw[:16], raw[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()


# ─── DES-CBC ─────────────────────────────────────────────────
class DESCipher:
    @staticmethod
    def _derive_key(password: str) -> bytes:
        return hashlib.md5(password.encode()).digest()[:8]

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        key = DESCipher._derive_key(password)
        iv  = os.urandom(8)
        padder = sym_padding.PKCS7(64).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(_TripleDES(key * 3), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct  = enc.update(padded) + enc.finalize()
        return base64.b64encode(iv + ct).decode()

    @staticmethod
    def decrypt(token: str, password: str) -> str:
        raw = base64.b64decode(token.encode())
        key, iv, ct = DESCipher._derive_key(password), raw[:8], raw[8:]
        cipher = Cipher(_TripleDES(key * 3), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = sym_padding.PKCS7(64).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()



# ─── AES-256-GCM ─────────────────────────────────────────────
class AESGCMCipher:
    """Authenticated encryption — detects tampering via GCM tag."""

    @staticmethod
    def _derive_key(password: str) -> bytes:
        return hashlib.sha256(password.encode()).digest()

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        key   = AESGCMCipher._derive_key(password)
        iv    = os.urandom(12)   # GCM standard: 96-bit nonce
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        enc   = cipher.encryptor()
        ct    = enc.update(plaintext.encode()) + enc.finalize()
        tag   = enc.tag                        # 16-byte auth tag
        # pack: iv(12) + tag(16) + ciphertext
        return base64.b64encode(iv + tag + ct).decode()

    @staticmethod
    def decrypt(token: str, password: str) -> str:
        raw   = base64.b64decode(token.encode())
        key   = AESGCMCipher._derive_key(password)
        iv    = raw[:12]
        tag   = raw[12:28]
        ct    = raw[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        dec   = cipher.decryptor()
        return (dec.update(ct) + dec.finalize()).decode()


# ─── ChaCha20-Poly1305 ───────────────────────────────────────
class ChaCha20Cipher:
    """Modern AEAD cipher — fast, secure, authenticated."""

    @staticmethod
    def _derive_key(password: str) -> bytes:
        return hashlib.sha256(password.encode()).digest()  # 256-bit key

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        key    = ChaCha20Cipher._derive_key(password)
        nonce  = os.urandom(12)   # 96-bit nonce
        chacha = ChaCha20Poly1305(key)
        ct     = chacha.encrypt(nonce, plaintext.encode(), None)
        # pack: nonce(12) + ciphertext+tag
        return base64.b64encode(nonce + ct).decode()

    @staticmethod
    def decrypt(token: str, password: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        raw    = base64.b64decode(token.encode())
        key    = ChaCha20Cipher._derive_key(password)
        nonce  = raw[:12]
        ct     = raw[12:]
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ct, None).decode()


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
        with open(RSA_PRIVATE_KEY_FILE, "wb") as f:
            f.write(cls._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(RSA_PUBLIC_KEY_FILE, "wb") as f:
            f.write(cls._public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    @classmethod
    def load_keys(cls) -> bool:
        if Path(RSA_PRIVATE_KEY_FILE).exists() and Path(RSA_PUBLIC_KEY_FILE).exists():
            with open(RSA_PRIVATE_KEY_FILE, "rb") as f:
                cls._private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(RSA_PUBLIC_KEY_FILE, "rb") as f:
                cls._public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            cprint("dim", "  ✓  RSA keys loaded from disk.")
            return True
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
        ct = base64.b64decode(token.encode())
        return cls._private_key.decrypt(
            ct,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

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
        except Exception:
            cprint("red", "  ✗ Decryption failed — wrong password or corrupted data.")


def run_des():
    choice = action_menu("DES (CBC)")
    if choice == "1":
        text = input(f"\n  {C['dim']}Plaintext : {C['reset']}")
        pwd  = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            token = DESCipher.encrypt(text, pwd)
            display_result("✓ DES Encrypted (Base64):", token, "orange")
            prompt_save(token, "DES", "encrypt")
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        pwd   = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            plain = DESCipher.decrypt(token, pwd)
            display_result("✓ DES Decrypted:", plain, "green")
            prompt_save(plain, "DES", "decrypt")
        except Exception:
            cprint("red", "  ✗ Decryption failed — wrong password or corrupted data.")


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
            cprint("red", f"  ✗ Decryption failed: {e}")

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
        except Exception:
            cprint("red", "  ✗ Decryption failed — wrong password, corrupted data, or tampered ciphertext.")


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
        except Exception:
            cprint("red", "  ✗ Decryption failed — wrong password, corrupted data, or tampered ciphertext.")



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
        ("[DES]          ", lambda: DESCipher.encrypt(text, pwd),       "orange"),
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
    print(f"  {C['orange']}[4]{C['reset']} DES          — Data Encryption Standard {C['dim']}(legacy){C['reset']}")
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
        description="CipherVault — Encrypt/decrypt text using AES-256-CBC, AES-256-GCM, ChaCha20-Poly1305, DES, or RSA-2048.",
        epilog="""
Examples:
  python3 cipher_vault.py --algo aes     --operation encrypt --text "hello" --password "mypass"
  python3 cipher_vault.py --algo aesgcm  --operation encrypt --text "hello" --password "mypass"
  python3 cipher_vault.py --algo chacha20 --operation encrypt --text "hello" --password "mypass"
  python3 cipher_vault.py --algo rsa     --operation encrypt --text "hello"
  python3 cipher_vault.py --algo aes     --operation decrypt --text "BASE64..." --password "mypass" --output
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