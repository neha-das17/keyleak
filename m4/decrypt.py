#!/usr/bin/env python3

import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# -------------------------------------------------
# Session file
# -------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

SESSION_FILE = BASE_DIR / "session.json"


# -------------------------------------------------
# Hexadecimal conversion
# -------------------------------------------------

def hex_to_bytes(name, value):

    value = value.strip().replace(" ", "")

    if len(value) % 2 != 0:

        raise ValueError(
            f"{name} has an odd number of hexadecimal characters"
        )

    try:

        return bytes.fromhex(value)

    except ValueError:

        raise ValueError(
            f"{name} contains invalid hexadecimal characters"
        )


# -------------------------------------------------
# AES-256-GCM decryption
# -------------------------------------------------

def decrypt_aes_gcm(
    key_hex,
    iv_hex,
    ciphertext_hex,
    tag_hex
):

    key = hex_to_bytes("Key", key_hex)

    iv = hex_to_bytes("IV", iv_hex)

    ciphertext = hex_to_bytes(
        "Ciphertext",
        ciphertext_hex
    )

    tag = hex_to_bytes(
        "Authentication tag",
        tag_hex
    )

    # Validate key
    if len(key) != 32:

        raise ValueError(
            "AES-256 requires exactly 32 key bytes"
        )

    # Validate IV
    if len(iv) != 12:

        raise ValueError(
            "GCM IV must be 12 bytes"
        )

    # Validate tag
    if len(tag) != 16:

        raise ValueError(
            "GCM authentication tag must be 16 bytes"
        )

    # Initialize AES-GCM
    aesgcm = AESGCM(key)

    # Ciphertext + authentication tag
    ciphertext_and_tag = ciphertext + tag

    # Decrypt
    plaintext = aesgcm.decrypt(
        iv,
        ciphertext_and_tag,
        None
    )

    return plaintext


# -------------------------------------------------
# Main M4
# -------------------------------------------------

def main():

    print("=" * 48)
    print("       KeyLeak - M4 Key Reconstruction")
    print("=" * 48)

    # -----------------------------------------
    # Load M3 session
    # -----------------------------------------

    if not SESSION_FILE.exists():

        print("\n[M4] ERROR: session.json not found.")
        print("[M4] Run exploit/leak.py first.")

        return 1

    with open(SESSION_FILE, "r") as f:

        session = json.load(f)

    key_hex = session["recovered_key"]

    iv_hex = session["iv"]

    ciphertext_hex = session["ciphertext"]

    tag_hex = session["tag"]

    print("\n[M4] Session data loaded successfully.")

    print("[M4] Recovered AES key:", key_hex)

    print("[M4] Key length:", len(key_hex) // 2, "bytes")

    print("\n[M4] Starting AES-256-GCM decryption...")

    # -----------------------------------------
    # Decrypt
    # -----------------------------------------

    try:

        plaintext = decrypt_aes_gcm(
            key_hex,
            iv_hex,
            ciphertext_hex,
            tag_hex
        )

        print("\n[M4] AES-256-GCM decryption: SUCCESS")

        print(
            "[M4] Recovered plaintext:",
            plaintext.decode("utf-8")
        )

        # -----------------------------------------
        # Verify plaintext
        # -----------------------------------------

        expected = b"Confidential KeyLeak message"

        print()

        if plaintext == expected:

            print("[M4] Plaintext verification: PASS")

            print(
                "[M4] Confidentiality broken: "
                "recovered key decrypts ciphertext."
            )

        else:

            print("[M4] Plaintext verification: FAIL")

            return 1

        return 0

    except InvalidTag:

        print("\n[M4] DECRYPTION FAILED")

        print(
            "[M4] Authentication failed. "
            "Key, IV, ciphertext or tag may be incorrect."
        )

        return 1

    except Exception as e:

        print("\n[M4] ERROR:", e)

        return 1


if __name__ == "__main__":

    raise SystemExit(main())
