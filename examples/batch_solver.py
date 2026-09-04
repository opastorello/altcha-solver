#!/usr/bin/env python3
"""
Batch solving example for Altcha Solver.

Demonstrates parallel pre-computation of multiple challenges.
"""

import sys
import os
import time
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from altcha_solver import AltchaSolver


def generate_mock_challenge(cost: int = 2000, prefix_len: int = 1) -> dict:
    """
    Generate a mock PBKDF2 challenge for testing.

    In production, you would fetch this from the server.
    """
    nonce = secrets.token_hex(16)
    salt = secrets.token_hex(16)

    # For testing, use a short prefix (more solutions, faster solve)
    key_prefix = "0" * (prefix_len * 2)  # Each byte = 2 hex chars

    return {
        "parameters": {
            "algorithm": "PBKDF2/SHA-256",
            "cost": cost,
            "keyLength": 32,
            "keyPrefix": key_prefix,
            "nonce": nonce,
            "salt": salt
        }
    }


def solve_single(challenge: dict, index: int) -> dict:
    """Solve a single challenge and return result with metadata."""
    solver = AltchaSolver()
    start = time.time()

    try:
        solution = solver.solve(challenge)
        return {
            "index": index,
            "success": True,
            "counter": solution["counter"],
            "time_ms": round((time.time() - start) * 1000, 1)
        }
    except RuntimeError as e:
        return {
            "index": index,
            "success": False,
            "error": str(e),
            "time_ms": round((time.time() - start) * 1000, 1)
        }


def main():
    # Configuration
    num_challenges = 10
    cost = 2000  # Lower cost = faster for demo
    workers = 4

    print("=" * 60)
    print("ALTCHA SOLVER - BATCH PROCESSING EXAMPLE")
    print("=" * 60)
    print()
    print(f"Challenges:  {num_challenges}")
    print(f"PBKDF2 Cost: {cost}")
    print(f"Workers:     {workers}")
    print()

    # Generate mock challenges (in production, fetch from server)
    print("Generating challenges...")
    challenges = [generate_mock_challenge(cost=cost) for _ in range(num_challenges)]

    # Solve in parallel
    print("Solving in parallel...")
    print("-" * 60)

    total_start = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(solve_single, ch, i): i
            for i, ch in enumerate(challenges)
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

            status = "OK" if result["success"] else "FAIL"
            counter_str = f"counter={result.get('counter', 'N/A'):5d}" if result["success"] else result.get("error", "")[:30]
            print(f"  [{result['index']:2d}] {status} | {result['time_ms']:7.1f}ms | {counter_str}")

    total_time = time.time() - total_start

    # Summary
    print("-" * 60)
    print()
    print("SUMMARY:")
    successful = [r for r in results if r["success"]]
    print(f"  Solved:      {len(successful)}/{num_challenges}")
    print(f"  Total time:  {total_time * 1000:.1f}ms")
    print(f"  Throughput:  {len(successful) / total_time:.1f} challenges/sec")

    if successful:
        avg_time = sum(r["time_ms"] for r in successful) / len(successful)
        print(f"  Avg solve:   {avg_time:.1f}ms")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
