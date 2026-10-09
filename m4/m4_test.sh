#!/bin/bash

KEY="$1"
IV="$2"
CIPHERTEXT="$3"
TAG="$4"

printf "%s\n%s\n%s\n%s\n" \
    "$KEY" \
    "$IV" \
    "$CIPHERTEXT" \
    "$TAG" | ./decrypt.py
