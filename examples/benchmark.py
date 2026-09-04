#!/usr/bin/env python3
"""
Performance benchmark for Altcha Solver.

Measures solving speed across different PBKDF2 cost values.
"""

import sys
import os
import time
import hashlib
import secrets
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def benchmark_pbkdf2_iterations(cost: int, iterations: int = 500) -> dict:
    """
    Benchmark raw PBKDF2 performance.

    Args:
        cost: PBKDF2 iteration count
        iterations: Number of PBKDF2 calls to perform

    Returns:
        Dict with timing statistics
    """
    nonce = bytes.fromhex("4db2e1ee6108476cba8972f39cf900b9")
    salt = bytes.fromhex("98b95a514955c35e73de9252423882a5")

    times = []

    for counter in range(iterations):
        password = nonce + counter.to_bytes(4, 'big')

        start = time.perf_counter()
        hashlib.pbkdf2_hmac('sha256', password, salt, cost, 32)
        elapsed = time.perf_counter() - start

        times.append(elapsed * 1000)  # Convert to ms

    return {
        "cost": cost,
        "iterations": iterations,
        "total_ms": sum(times),
        "avg_ms": statistics.mean(times),
        "min_ms": min(times),
        "max_ms": max(times),
        "iter_per_sec": iterations / (sum(times) / 1000)
    }


def benchmark_solve(cost: int, trials: int = 5) -> dict:
    """
    Benchmark full solve operation.

    Args:
        cost: PBKDF2 cost parameter
        trials: Number of solves to perform

    Returns:
        Dict with solve statistics
    """
    from altcha_solver import AltchaSolver

    solve_times = []
    counters = []

    for _ in range(trials):
        # Generate random challenge with short prefix (quick to solve)
        challenge = {
            "parameters": {
                "algorithm": "PBKDF2/SHA-256",
                "cost": cost,
                "keyLength": 32,
                "keyPrefix": "00",
                "nonce": secrets.token_hex(16),
                "salt": secrets.token_hex(16)
            }
        }

        solver = AltchaSolver()
        start = time.perf_counter()
        solution = solver.solve(challenge)
        elapsed = time.perf_counter() - start

        solve_times.append(elapsed * 1000)
        counters.append(solution["counter"])

    return {
        "cost": cost,
        "trials": trials,
        "avg_solve_ms": statistics.mean(solve_times),
        "min_solve_ms": min(solve_times),
        "max_solve_ms": max(solve_times),
        "avg_counter": statistics.mean(counters),
        "max_counter": max(counters)
    }


def main():
    print("=" * 70)
    print("ALTCHA SOLVER PERFORMANCE BENCHMARK")
    print("=" * 70)
    print()

    # Benchmark 1: Raw PBKDF2 performance
    print("BENCHMARK 1: PBKDF2 Iteration Performance")
    print("-" * 70)
    print(f"{'Cost':>8} | {'Iters':>6} | {'Total (ms)':>12} | {'Avg (ms)':>10} | {'Iter/sec':>10}")
    print("-" * 70)

    for cost in [1000, 2000, 3000, 5000, 10000]:
        result = benchmark_pbkdf2_iterations(cost, iterations=100)
        print(f"{result['cost']:>8} | {result['iterations']:>6} | {result['total_ms']:>12.1f} | {result['avg_ms']:>10.3f} | {result['iter_per_sec']:>10.1f}")

    print()

    # Benchmark 2: Full solve performance
    print("BENCHMARK 2: Full Solve Performance (prefix='00')")
    print("-" * 70)
    print(f"{'Cost':>8} | {'Trials':>6} | {'Avg (ms)':>12} | {'Min (ms)':>10} | {'Max (ms)':>10} | {'Avg Counter':>12}")
    print("-" * 70)

    for cost in [1000, 2000, 5000]:
        result = benchmark_solve(cost, trials=5)
        print(f"{result['cost']:>8} | {result['trials']:>6} | {result['avg_solve_ms']:>12.1f} | {result['min_solve_ms']:>10.1f} | {result['max_solve_ms']:>10.1f} | {result['avg_counter']:>12.1f}")

    print()

    # Summary
    print("ANALYSIS")
    print("-" * 70)
    print("- PBKDF2 cost has linear relationship with computation time")
    print("- cost=2000 is ~2.5x faster than cost=5000")
    print("- Short prefixes ('00') typically solve in <1000 iterations")
    print("- Parallel pre-computation can achieve high throughput")
    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
