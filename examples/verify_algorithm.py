#!/usr/bin/env python3
"""
Complete algorithm verification for Altcha Solver.

Tests ALL 8 supported algorithms against known values and validates:
- Correct solution finding
- Proper prefix matching
- Solution verification
- Multiple valid solutions for short prefixes
"""

import sys
import os
import hashlib
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from altcha_solver import AltchaSolver, ARGON2_AVAILABLE


# Test data (from Altcha Playground)
NONCE = "4db2e1ee6108476cba8972f39cf900b9"
SALT = "98b95a514955c35e73de9252423882a5"


def test_pbkdf2_sha256():
    """Test PBKDF2/SHA-256 algorithm."""
    print("Test 1: PBKDF2/SHA-256")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "PBKDF2/SHA-256",
            "nonce": NONCE,
            "salt": SALT,
            "cost": 2000,
            "keyLength": 32,
            "keyPrefix": "00"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["derivedKey"].startswith("00"), "Key should start with '00'"
    assert solver.verify_solution(challenge["parameters"], solution), "Solution should verify"

    print(f"  Counter:  {solution['counter']}")
    print(f"  Key:      {solution['derivedKey'][:32]}...")
    print(f"  Verified: PASS")
    print()
    return True


def test_pbkdf2_sha384():
    """Test PBKDF2/SHA-384 algorithm."""
    print("Test 2: PBKDF2/SHA-384")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "PBKDF2/SHA-384",
            "nonce": NONCE,
            "salt": SALT,
            "cost": 2000,
            "keyLength": 48,
            "keyPrefix": "00"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["derivedKey"].startswith("00"), "Key should start with '00'"
    assert solver.verify_solution(challenge["parameters"], solution), "Solution should verify"

    print(f"  Counter:  {solution['counter']}")
    print(f"  Key:      {solution['derivedKey'][:32]}...")
    print(f"  Verified: PASS")
    print()
    return True


def test_pbkdf2_sha512():
    """Test PBKDF2/SHA-512 algorithm."""
    print("Test 3: PBKDF2/SHA-512")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "PBKDF2/SHA-512",
            "nonce": NONCE,
            "salt": SALT,
            "cost": 2000,
            "keyLength": 64,
            "keyPrefix": "00"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["derivedKey"].startswith("00"), "Key should start with '00'"
    assert solver.verify_solution(challenge["parameters"], solution), "Solution should verify"

    print(f"  Counter:  {solution['counter']}")
    print(f"  Key:      {solution['derivedKey'][:32]}...")
    print(f"  Verified: PASS")
    print()
    return True


def test_sha256():
    """Test SHA-256 algorithm (prefix mode)."""
    print("Test 4: SHA-256 (prefix mode)")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "SHA-256",
            "nonce": NONCE,
            "keyPrefix": "00"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["derivedKey"].startswith("00"), "Key should start with '00'"
    assert solver.verify_solution(challenge["parameters"], solution), "Solution should verify"

    print(f"  Counter:  {solution['counter']}")
    print(f"  Key:      {solution['derivedKey'][:32]}...")
    print(f"  Verified: PASS")
    print()
    return True


def test_sha384():
    """Test SHA-384 algorithm (prefix mode)."""
    print("Test 5: SHA-384 (prefix mode)")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "SHA-384",
            "nonce": NONCE,
            "keyPrefix": "00"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["derivedKey"].startswith("00"), "Key should start with '00'"
    assert solver.verify_solution(challenge["parameters"], solution), "Solution should verify"

    print(f"  Counter:  {solution['counter']}")
    print(f"  Key:      {solution['derivedKey'][:32]}...")
    print(f"  Verified: PASS")
    print()
    return True


def test_sha512():
    """Test SHA-512 algorithm (prefix mode)."""
    print("Test 6: SHA-512 (prefix mode)")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "SHA-512",
            "nonce": NONCE,
            "keyPrefix": "00"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["derivedKey"].startswith("00"), "Key should start with '00'"
    assert solver.verify_solution(challenge["parameters"], solution), "Solution should verify"

    print(f"  Counter:  {solution['counter']}")
    print(f"  Key:      {solution['derivedKey'][:32]}...")
    print(f"  Verified: PASS")
    print()
    return True


def test_scrypt():
    """Test Scrypt algorithm."""
    print("Test 7: SCRYPT")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "SCRYPT",
            "nonce": NONCE,
            "salt": SALT,
            "cost": 1024,
            "memoryCost": 8,
            "parallelism": 1,
            "keyLength": 32,
            "keyPrefix": "0"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["derivedKey"].startswith("0"), "Key should start with '0'"
    assert solver.verify_solution(challenge["parameters"], solution), "Solution should verify"

    print(f"  Counter:  {solution['counter']}")
    print(f"  Key:      {solution['derivedKey'][:32]}...")
    print(f"  Verified: PASS")
    print()
    return True


def test_argon2():
    """Test Argon2id algorithm."""
    print("Test 8: ARGON2ID")
    print("-" * 40)

    if not ARGON2_AVAILABLE:
        print("  SKIPPED (argon2-cffi not installed)")
        print()
        return None

    challenge = {
        "parameters": {
            "algorithm": "ARGON2ID",
            "nonce": NONCE,
            "salt": SALT,
            "cost": 2,
            "memoryCost": 1024,
            "parallelism": 1,
            "keyLength": 32,
            "keyPrefix": "0"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["derivedKey"].startswith("0"), "Key should start with '0'"
    assert solver.verify_solution(challenge["parameters"], solution), "Solution should verify"

    print(f"  Counter:  {solution['counter']}")
    print(f"  Key:      {solution['derivedKey'][:32]}...")
    print(f"  Verified: PASS")
    print()
    return True


def test_exact_counter():
    """Test that long prefix finds exact counter."""
    print("Test 9: Exact counter match (long prefix)")
    print("-" * 40)

    nonce_bytes = bytes.fromhex(NONCE)
    salt_bytes = bytes.fromhex(SALT)
    target_counter = 1234
    cost = 2000

    # Generate prefix from target counter
    password = nonce_bytes + target_counter.to_bytes(4, 'big')
    key = hashlib.pbkdf2_hmac('sha256', password, salt_bytes, cost, 32)
    prefix = key.hex()[:16]  # 8 bytes

    challenge = {
        "parameters": {
            "algorithm": "PBKDF2/SHA-256",
            "nonce": NONCE,
            "salt": SALT,
            "cost": cost,
            "keyLength": 32,
            "keyPrefix": prefix
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    assert solution["counter"] == target_counter, f"Expected {target_counter}, got {solution['counter']}"

    print(f"  Target:   {target_counter}")
    print(f"  Found:    {solution['counter']}")
    print(f"  Verified: PASS")
    print()
    return True


def test_multiple_solutions():
    """Test that short prefix allows multiple valid solutions."""
    print("Test 10: Multiple valid solutions")
    print("-" * 40)

    nonce_bytes = bytes.fromhex(NONCE)
    salt_bytes = bytes.fromhex(SALT)
    cost = 2000
    prefix = "00"

    valid_counters = []
    for counter in range(1000):
        password = nonce_bytes + counter.to_bytes(4, 'big')
        key = hashlib.pbkdf2_hmac('sha256', password, salt_bytes, cost, 32)
        if key.hex().startswith(prefix):
            valid_counters.append(counter)

    assert len(valid_counters) > 1, "Should find multiple valid counters"

    print(f"  Prefix:   '{prefix}'")
    print(f"  Range:    0-999")
    print(f"  Found:    {valid_counters}")
    print(f"  Count:    {len(valid_counters)}")
    print(f"  Verified: PASS")
    print()
    return True


def test_payload_encoding():
    """Test base64 payload encoding."""
    print("Test 11: Payload encoding")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "PBKDF2/SHA-256",
            "nonce": NONCE,
            "salt": SALT,
            "cost": 2000,
            "keyLength": 32,
            "keyPrefix": "00"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)
    payload = solver.build_payload(challenge, solution)

    import base64
    import json

    # Decode and verify structure
    decoded = json.loads(base64.b64decode(payload))
    assert "challenge" in decoded, "Payload should contain challenge"
    assert "solution" in decoded, "Payload should contain solution"
    assert decoded["solution"]["counter"] == solution["counter"], "Counter should match"

    print(f"  Payload:  {payload[:40]}...")
    print(f"  Length:   {len(payload)} chars")
    print(f"  Verified: PASS")
    print()
    return True


def test_verification():
    """Test solution verification methods."""
    print("Test 12: Solution verification")
    print("-" * 40)

    challenge = {
        "parameters": {
            "algorithm": "PBKDF2/SHA-256",
            "nonce": NONCE,
            "salt": SALT,
            "cost": 2000,
            "keyLength": 32,
            "keyPrefix": "00"
        }
    }

    solver = AltchaSolver()
    solution = solver.solve(challenge)

    # Valid solution
    assert solver.verify_solution(challenge["parameters"], solution), "Valid should verify"

    # Invalid solution
    invalid = {"counter": 99999, "derivedKey": "invalid"}
    assert not solver.verify_solution(challenge["parameters"], invalid), "Invalid should not verify"

    print(f"  Valid:    PASS")
    print(f"  Invalid:  PASS")
    print()
    return True


def main():
    print("=" * 60)
    print("ALTCHA SOLVER - COMPLETE ALGORITHM VERIFICATION")
    print("=" * 60)
    print()

    tests = [
        ("PBKDF2/SHA-256", test_pbkdf2_sha256),
        ("PBKDF2/SHA-384", test_pbkdf2_sha384),
        ("PBKDF2/SHA-512", test_pbkdf2_sha512),
        ("SHA-256", test_sha256),
        ("SHA-384", test_sha384),
        ("SHA-512", test_sha512),
        ("SCRYPT", test_scrypt),
        ("ARGON2ID", test_argon2),
        ("Exact Counter", test_exact_counter),
        ("Multiple Solutions", test_multiple_solutions),
        ("Payload Encoding", test_payload_encoding),
        ("Verification", test_verification),
    ]

    passed = 0
    failed = 0
    skipped = 0

    for name, test in tests:
        try:
            result = test()
            if result is True:
                passed += 1
            elif result is None:
                skipped += 1
        except AssertionError as e:
            print(f"  FAILED: {e}")
            print()
            failed += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            print()
            failed += 1

    print("=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed, {skipped} skipped")
    print("=" * 60)

    if failed == 0:
        print()
        print("ALL TESTS PASSED!")
        print("Altcha Solver supports all 8 algorithm variants.")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
