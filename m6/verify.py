#!/usr/bin/env python3

import subprocess
import re
import csv
from pathlib import Path


# =====================================================
# KEYLEAK - M6 RE-EXPLOITATION AND VERIFICATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parent.parent

VULNERABLE_SERVER = BASE_DIR / "vulnerable" / "server"

PATCHED_SERVER = BASE_DIR / "patched" / "server_patched"

RESULTS_FILE = BASE_DIR / "m6" / "results.csv"


# =====================================================
# TEST PAYLOADS
# =====================================================

TESTS = [
    {
        "id": "T1",
        "name": "Maximum-length input",
        "payload": b"A" * 64 + b"\n",
        "length": 64
    },
    {
        "id": "T2",
        "name": "One byte beyond limit",
        "payload": b"A" * 65 + b"\n",
        "length": 65
    },
    {
        "id": "T3",
        "name": "Oversized input",
        "payload": b"B" * 128 + b"\n",
        "length": 128
    }
]


# =====================================================
# RUN TARGET APPLICATION
# =====================================================

def run_target(binary, payload):

    try:
        process = subprocess.run(
            [str(binary)],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )

        return {
            "stdout": process.stdout.decode(
                errors="replace"
            ),
            "stderr": process.stderr.decode(
                errors="replace"
            ),
            "returncode": process.returncode
        }

    except subprocess.TimeoutExpired:

        return {
            "stdout": "",
            "stderr": "Execution timed out",
            "returncode": -999
        }

    except OSError as e:

        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -998
        }


# =====================================================
# EXTRACT HEXADECIMAL OUTPUT
# =====================================================

def extract_hex(output, label):

    pattern = re.escape(label) + r"\s*([0-9a-fA-F]+)"

    match = re.search(pattern, output)

    if match:
        return match.group(1).lower()

    return None


# =====================================================
# ANALYZE VULNERABLE APPLICATION
# =====================================================

def analyze_vulnerable(result):

    output = result["stdout"]

    original_key = extract_hex(
        output,
        "[M1] Original key:"
    )

    leaked_region = extract_hex(
        output,
        "[M3] Leak in hex:"
    )

    key_recovered = False
    key_matches = False

    if leaked_region is not None:

        try:
            leaked_bytes = bytes.fromhex(leaked_region)

            if len(leaked_bytes) == 96:

                recovered_key = leaked_bytes[64:96]

                key_recovered = (
                    len(recovered_key) == 32
                )

                if original_key is not None:

                    key_matches = (
                        recovered_key.hex()
                        == original_key
                    )

        except ValueError:
            pass

    aes_pass = (
        "[M1] AES-256-GCM test: PASS"
        in output
    )

    return {
        "key_recovered": key_recovered,
        "key_matches": key_matches,
        "aes_pass": aes_pass
    }


# =====================================================
# ANALYZE PATCHED APPLICATION
# =====================================================

def analyze_patched(result):

    output = result["stdout"]

    aes_pass = (
        "[M5] AES-GCM self-test: PASS"
        in output
    )

    leak_present = (
        "[M3] Leak in hex:"
        in output
        or
        "[M1] Original key:"
        in output
    )

    oversized_rejected = (
        "Input rejected: exceeds 64 bytes."
        in output
    )

    input_accepted = (
        "[M5] Accepted"
        in output
    )

    cleanup_invoked = (
        "[M5] Sensitive buffers cleansed"
        in output
    )

    return {
        "aes_pass": aes_pass,
        "leak_present": leak_present,
        "oversized_rejected": oversized_rejected,
        "input_accepted": input_accepted,
        "cleanup_invoked": cleanup_invoked
    }


# =====================================================
# MAIN VERIFICATION
# =====================================================

def main():

    print("=" * 60)
    print("       KeyLeak - M6 Security Verification")
    print("=" * 60)

    if not VULNERABLE_SERVER.exists():
        print("ERROR: Vulnerable server not found.")
        return 1

    if not PATCHED_SERVER.exists():
        print("ERROR: Patched server not found.")
        return 1

    results = []

    for test in TESTS:

        print("\n" + "=" * 60)

        print(
            f"{test['id']} - {test['name']}"
        )

        print(
            f"Payload length: {test['length']} bytes"
        )

        print("=" * 60)

        # -----------------------------------------
        # Vulnerable target
        # -----------------------------------------

        vulnerable_result = run_target(
            VULNERABLE_SERVER,
            test["payload"]
        )

        vulnerable = analyze_vulnerable(
            vulnerable_result
        )

        print("\n[VULNERABLE APPLICATION]")

        print(
            "AES-GCM self-test:",
            "PASS" if vulnerable["aes_pass"]
            else "FAIL"
        )

        print(
            "32-byte key recovered:",
            "YES" if vulnerable["key_recovered"]
            else "NO"
        )

        print(
            "Recovered key matches original:",
            "YES" if vulnerable["key_matches"]
            else "NO"
        )

        # -----------------------------------------
        # Patched target
        # -----------------------------------------

        patched_result = run_target(
            PATCHED_SERVER,
            test["payload"]
        )

        patched = analyze_patched(
            patched_result
        )

        print("\n[PATCHED APPLICATION]")

        print(
            "AES-GCM self-test:",
            "PASS" if patched["aes_pass"]
            else "FAIL"
        )

        print(
            "Key disclosure output:",
            "PRESENT" if patched["leak_present"]
            else "NOT PRESENT"
        )

        print(
            "Oversized input rejected:",
            "YES" if patched["oversized_rejected"]
            else "NO"
        )

        print(
            "Input accepted:",
            "YES" if patched["input_accepted"]
            else "NO"
        )

        print(
            "Cleanup invoked:",
            "YES" if patched["cleanup_invoked"]
            else "NO"
        )

        # -----------------------------------------
        # Overall test assessment
        # -----------------------------------------

        expected_rejection = (
            test["length"] > 64
        )

        vulnerable_exposed = (
            vulnerable["key_recovered"]
            and vulnerable["key_matches"]
        )

        patched_safe = (
            patched["aes_pass"]
            and not patched["leak_present"]
            and patched["cleanup_invoked"]
            and (
                patched["oversized_rejected"]
                if expected_rejection
                else patched["input_accepted"]
            )
        )

        test_pass = (
            vulnerable_exposed
            and vulnerable["aes_pass"]
            and patched_safe
        )

        print("\n[SECURITY COMPARISON]")

        print(
            "Result:",
            "PASS" if test_pass else "FAIL"
        )

        results.append({
            "Test ID": test["id"],
            "Payload Length": test["length"],
            "Vulnerable AES": vulnerable["aes_pass"],
            "Vulnerable Key Recovered":
                vulnerable["key_recovered"],
            "Vulnerable Key Matches":
                vulnerable["key_matches"],
            "Patched AES": patched["aes_pass"],
            "Patched Key Disclosure":
                patched["leak_present"],
            "Patched Oversized Rejected":
                patched["oversized_rejected"],
            "Patched Cleanup Invoked":
                patched["cleanup_invoked"],
            "Result": "PASS" if test_pass else "FAIL"
        })

    # =================================================
    # SAVE RESULTS
    # =================================================

    RESULTS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(RESULTS_FILE, "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=results[0].keys()
        )

        writer.writeheader()

        writer.writerows(results)

    print("\n" + "=" * 60)
    print("       M6 FINAL SUMMARY")
    print("=" * 60)

    passed = sum(
        1 for row in results
        if row["Result"] == "PASS"
    )

    print(f"\nTotal tests: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {len(results) - passed}")

    print("\nResults saved to:")
    print(RESULTS_FILE)

    if passed == len(results):
        print("\n[M6] SECURITY VERIFICATION: PASS")
        return 0

    print("\n[M6] SECURITY VERIFICATION: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
