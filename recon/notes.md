# KeyLeak Reconnaissance

## M1

The AES-256-GCM implementation successfully generates a random
32-byte key, encrypts the plaintext, and decrypts it successfully.

## Initial stack analysis

The original server binary was inspected using GDB.

Important addresses:

- RBP: 0x7fffffffdd90
- input: 0x7fffffffdd40
- key: 0x7fffffffdca0

The measured distance between input and key was 160 bytes.

The key was confirmed to occupy 32 bytes.

## Important observation

The original program uses:

    fgets(input, sizeof(input), stdin)

This is a bounded input operation and does not provide the
buffer-overflow primitive required for the vulnerable demonstration.

Therefore a separate controlled vulnerable configuration is required
for M2/M3.
