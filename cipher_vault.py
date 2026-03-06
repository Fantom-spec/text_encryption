"""
╔═══════════════════════════════════════════╗
║         CIPHERVAULT — Text Encryption     ║
║   Supports: AES-256, DES, RSA-2048        ║
╚═══════════════════════════════════════════╝
"""

import os
import base64
import hashlib
import textwrap

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
    "reset":  "\033[0m",
    "cyan":   "\033[36m",
    "green":  "\033[32m",
    "orange": "\033[33m",
    "red":    "\033[31m",
    "dim":    "\033[90m",
    "bold":   "\033[1m",
    "white":  "\033[97m",
}

def cprint(color, text):
    print(f"{C[color]}{text}{C['reset']}")

def header(title, color="cyan"):
    line = "─" * 54
    print(f"\n{C[color]}┌{line}┐")
    print(f"│  {title:<52}│")
    print(f"└{line}┘{C['reset']}")


# ─── AES-256-CBC ─────────────────────────────────────────────
class AESCipher:
    KEY_SIZE = 32   # 256-bit

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
        ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
        # re-create encryptor (it's one-shot)
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
        return hashlib.md5(password.encode()).digest()[:8]  # DES = 64-bit key

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


# ─── RSA-2048 ────────────────────────────────────────────────
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
        cprint("green", "  ✓  Key pair generated successfully.")

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        if cls._public_key is None:
            cls.generate_keys()
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
        if cls._private_key is None:
            raise ValueError("No private key available. Encrypt something first.")
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
        if cls._public_key is None:
            return "No key generated yet."
        return cls._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()


# ─── Display Helpers ─────────────────────────────────────────
def display_result(label: str, value: str, color: str = "green"):
    print(f"\n  {C[color]}{C['bold']}{label}{C['reset']}")
    print(f"  {C['white']}{value}{C['reset']}")

def algo_menu():
    header("SELECT ALGORITHM")
    print(f"  {C['cyan']}[1]{C['reset']} AES-256   — Advanced Encryption Standard {C['dim']}(recommended){C['reset']}")
    print(f"  {C['orange']}[2]{C['reset']} DES       — Data Encryption Standard {C['dim']}(legacy){C['reset']}")
    print(f"  {C['green']}[3]{C['reset']} RSA-2048  — Asymmetric / Public-Key Encryption")
    print(f"  {C['dim']}[4]{C['reset']} Compare All Algorithms on Same Text")
    print(f"  {C['red']}[0]{C['reset']} Exit")
    return input(f"\n  {C['dim']}>{C['reset']} ").strip()

def action_menu(algo: str):
    header(f"ACTION — {algo}")
    print(f"  {C['cyan']}[1]{C['reset']} Encrypt")
    print(f"  {C['orange']}[2]{C['reset']} Decrypt")
    if algo == "RSA":
        print(f"  {C['green']}[3]{C['reset']} Show Public Key")
    print(f"  {C['dim']}[0]{C['reset']} Back")
    return input(f"\n  {C['dim']}>{C['reset']} ").strip()


# ─── Handlers ────────────────────────────────────────────────
def run_aes():
    choice = action_menu("AES-256-CBC")
    if choice == "1":
        text = input(f"\n  {C['dim']}Plaintext : {C['reset']}")
        pwd  = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            token = AESCipher.encrypt(text, pwd)
            display_result("✓ AES-256 Encrypted (Base64):", token, "cyan")
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        pwd   = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            plain = AESCipher.decrypt(token, pwd)
            display_result("✓ AES-256 Decrypted:", plain, "green")
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
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        pwd   = input(f"  {C['dim']}Password  : {C['reset']}")
        try:
            plain = DESCipher.decrypt(token, pwd)
            display_result("✓ DES Decrypted:", plain, "green")
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
        except Exception as e:
            cprint("red", f"  ✗ Error: {e}")

    elif choice == "2":
        token = input(f"\n  {C['dim']}Ciphertext: {C['reset']}")
        try:
            plain = RSACipher.decrypt(token)
            display_result("✓ RSA-2048 Decrypted:", plain, "green")
        except Exception as e:
            cprint("red", f"  ✗ Decryption failed: {e}")

    elif choice == "3":
        header("RSA PUBLIC KEY", "green")
        print(f"{C['dim']}{RSACipher.export_public_key()}{C['reset']}")


def run_compare():
    header("COMPARE ALL ALGORITHMS")
    text = input(f"  {C['dim']}Enter text to encrypt : {C['reset']}")
    pwd  = input(f"  {C['dim']}Password (AES & DES)  : {C['reset']}")

    if len(text.encode()) > 190:
        cprint("orange", "  ⚠  Text too long for RSA — RSA result will be skipped.")

    print(f"\n  {C['dim']}{'─'*54}{C['reset']}")

    # AES
    try:
        aes_ct = AESCipher.encrypt(text, pwd)
        display_result(f"[AES-256]  {len(aes_ct)} chars", aes_ct[:64] + ("…" if len(aes_ct) > 64 else ""), "cyan")
    except Exception as e:
        cprint("red", f"  AES Error: {e}")

    # DES
    try:
        des_ct = DESCipher.encrypt(text, pwd)
        display_result(f"[DES]      {len(des_ct)} chars", des_ct[:64] + ("…" if len(des_ct) > 64 else ""), "orange")
    except Exception as e:
        cprint("red", f"  DES Error: {e}")

    # RSA
    if len(text.encode()) <= 190:
        try:
            rsa_ct = RSACipher.encrypt(text)
            display_result(f"[RSA-2048] {len(rsa_ct)} chars", rsa_ct[:64] + ("…" if len(rsa_ct) > 64 else ""), "green")
        except Exception as e:
            cprint("red", f"  RSA Error: {e}")

    print(f"\n  {C['dim']}{'─'*54}")
    cprint("dim", "  Note: RSA produces larger ciphertext; AES is fastest for bulk data.")


# ─── Main Loop ───────────────────────────────────────────────
def main():
    print(BANNER)
    cprint("dim", "  Secure text encryption using industry-standard algorithms.\n")

    while True:
        choice = algo_menu()
        if choice == "1":
            run_aes()
        elif choice == "2":
            run_des()
        elif choice == "3":
            run_rsa()
        elif choice == "4":
            run_compare()
        elif choice == "0":
            cprint("cyan", "\n  🔒 Session closed. Stay secure.\n")
            break
        else:
            cprint("red", "  Invalid choice. Try again.")


if __name__ == "__main__":
    main()