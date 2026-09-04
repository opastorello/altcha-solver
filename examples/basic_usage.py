#!/usr/bin/env python3
"""
Basic usage example for Altcha Solver.

This example demonstrates solving a PBKDF2 challenge from the Altcha Playground.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from altcha_solver import AltchaSolver


def main():
    # Challenge from Altcha Playground (https://playground.altcha.org/#/pow)
    # Algorithm: PBKDF2/SHA-256, Cost: 5000, Prefix: "00"
    challenge = {
        "parameters": {
            "algorithm": "PBKDF2/SHA-256",
            "cost": 5000,
            "keyLength": 32,
            "keyPrefix": "00",
            "nonce": "4db2e1ee6108476cba8972f39cf900b9",
            "salt": "98b95a514955c35e73de9252423882a5",
            "memoryCost": 0
        },
        "signature": "7b2de5af270b98601e44236e1b54e1db7d3b6eed12f1d4790281d6b7f8ef34bb"
    }

    print("=" * 60)
    print("ALTCHA SOLVER - BASIC USAGE EXAMPLE")
    print("=" * 60)
    print()
    print("Challenge Parameters:")
    print(f"  Algorithm:  {challenge['parameters']['algorithm']}")
    print(f"  Nonce:      {challenge['parameters']['nonce']}")
    print(f"  Salt:       {challenge['parameters']['salt']}")
    print(f"  Cost:       {challenge['parameters']['cost']}")
    print(f"  Key Length: {challenge['parameters']['keyLength']}")
    print(f"  Key Prefix: {challenge['parameters']['keyPrefix']}")
    print()

    # Create solver and solve
    solver = AltchaSolver()

    print("Solving...")
    solution = solver.solve(challenge)

    print()
    print("Solution Found:")
    print(f"  Counter:     {solution['counter']}")
    print(f"  Derived Key: {solution['derivedKey']}")
    print(f"  Time:        {solution['time']}ms")
    print()

    # Verify the solution
    is_valid = solver.verify_solution(challenge["parameters"], solution)
    print(f"Verification: {'VALID' if is_valid else 'INVALID'}")
    print()

    # Build payload for submission
    payload = solver.build_payload(challenge, solution)
    print("Base64 Payload (for submission):")
    print(f"  {payload[:60]}...")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
