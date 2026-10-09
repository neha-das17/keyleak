#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def hex_to_bytes(name, value):
    """Convert a hexadecimal string to bytes with validation."""
    value = value.strip().replace(" ", "")

    if len(value) % 2 != 0:
        raise ValueError(f"{name} has an odd number of hexadecimal characters")

    try:
        data = bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{name} contains invalid hexadecimal characters")

    return data


def decrypt_aes_gcm(key_hex, iv_hex, ciphertext_hex, tag_hex):
    """Decrypt AES-256-GCM ciphertext."""

    key = hex_to_bytes("Key", key_hex)
    iv = hex_to_bytes("IV", iv_hex)
    ciphertext = hex_to_bytes("Ciphertext", ciphertext_hex)
    tag = hex_to_bytes("Authentication tag", tag_hex)

    # AES-256 requires exactly 32 bytes.
    if len(key) != 32:
        raise ValueError(
            f"Invalid AES-256 key length: {len(key)} bytes. Expected 32 bytes."
        )

    # Our KeyLeak application uses a 12-byte GCM IV.
    if len(iv) != 12:
        raise ValueError(
            f"Invalid GCM IV length: {len(iv)} bytes. Expected 12 bytes."
        )

    # The KeyLeak application uses a 16-byte GCM authentication tag.
    if len(tag) != 16:
        raise ValueError(
            f"Invalid authentication tag length: {len(tag)} bytes. Expected 16 bytes."
        )

    aesgcm = AESGCM(key)

    # AESGCM expects ciphertext || authentication_tag.
    ciphertext_and_tag = ciphertext + tag

    plaintext = aesgcm.decrypt(
        iv,
        ciphertext_and_tag,
        None
    )

    return plaintext


def main():
    print("=" * 48)
    print("       KeyLeak - M4 Key Reconstruction")
    print("=" * 48)

    # These values must all come from THE SAME server execution.
    key_hex = input("[M4] Recovered AES-256 key: ").strip()
    iv_hex = input("[M4] IV: ").strip()
    ciphertext_hex = input("[M4] Ciphertext: ").strip()
    tag_hex = input("[M4] Authentication tag: ").strip()

    try:
        plaintext = decrypt_aes_gcm(
            key_hex,
            iv_hex,
            ciphertext_hex,
            tag_hex
        )

        print()
        print("[M4] Key length: 32 bytes")
        print("[M4] AES-256-GCM decryption: SUCCESS")
        print("[M4] Recovered plaintext:", plaintext.decode("utf-8"))

        expected = b"Confidential KeyLeak message"

        print()

        if plaintext == expected:
            print("[M4] Plaintext verification: PASS")
            print("[M4] Confidentiality broken: recovered key decrypts ciphertext.")
        else:
            print("[M4] Plaintext verification: FAIL")
            print("[M4] Decryption succeeded, but plaintext does not match expected value.")

    except Exception as e:
        print()
        print("[M4] DECRYPTION FAILED")
        print("[M4] Error:", e)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
