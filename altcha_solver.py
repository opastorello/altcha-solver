#!/usr/bin/env python3
"""
Altcha Solver - Universal Proof-of-Work CAPTCHA Solver

A complete implementation supporting ALL Altcha algorithm variants:
  - SHA-256, SHA-384, SHA-512 (hash matching)
  - PBKDF2/SHA-256, PBKDF2/SHA-384, PBKDF2/SHA-512 (key derivation)
  - Argon2id (memory-hard, requires argon2-cffi)
  - Scrypt (memory-hard, native Python 3.6+)

Usage:
    python altcha_solver.py <algorithm> [options]

Examples:
    python altcha_solver.py pbkdf2 --nonce NONCE --salt SALT --cost 5000 --prefix "00"
    python altcha_solver.py sha256 --salt SALT --challenge HASH
    python altcha_solver.py scrypt --nonce NONCE --salt SALT --cost 16384 --prefix "00"
"""

import hashlib
import json
import base64
import time
import argparse
from typing import Dict, Any, Optional, Tuple

# Optional: Argon2 support (pip install argon2-cffi)
try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class AltchaSolver:
    """
    Universal Altcha proof-of-work solver.

    Supports all Altcha algorithm variants:
        - SHA-256/384/512: Simple hash matching (legacy)
        - PBKDF2/SHA-256/384/512: Key derivation with prefix matching
        - Argon2id: Memory-hard key derivation (requires argon2-cffi)
        - Scrypt: Memory-hard key derivation (native Python)

    Attributes:
        max_iterations: Maximum counter values to try before giving up
        supported_algorithms: List of all supported algorithm names
    """

    SUPPORTED_ALGORITHMS = [
        "SHA-256", "SHA-384", "SHA-512",
        "PBKDF2/SHA-256", "PBKDF2/SHA-384", "PBKDF2/SHA-512",
        "ARGON2ID", "SCRYPT"
    ]

    # Map algorithm names to hashlib names
    HASH_MAP = {
        "SHA-256": "sha256",
        "SHA-384": "sha384",
        "SHA-512": "sha512",
        "PBKDF2/SHA-256": "sha256",
        "PBKDF2/SHA-384": "sha384",
        "PBKDF2/SHA-512": "sha512",
    }

    # Default key lengths for each algorithm
    KEY_LENGTHS = {
        "SHA-256": 32,
        "SHA-384": 48,
        "SHA-512": 64,
        "PBKDF2/SHA-256": 32,
        "PBKDF2/SHA-384": 48,
        "PBKDF2/SHA-512": 64,
        "ARGON2ID": 32,
        "SCRYPT": 32,
    }

    def __init__(self, max_iterations: int = 100000):
        """
        Initialize solver.

        Args:
            max_iterations: Maximum counter values to try before giving up
        """
        self.max_iterations = max_iterations

    def solve(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Solve an Altcha challenge.

        Automatically detects algorithm type and dispatches to appropriate solver.

        Args:
            challenge: Challenge object from server containing 'parameters'

        Returns:
            Solution dict with:
                - counter: The found counter value
                - derivedKey/hash: The computed key or hash
                - time: Solving time in milliseconds

        Raises:
            ValueError: If algorithm is unsupported
            RuntimeError: If no solution found within max_iterations
        """
        params = challenge.get("parameters", challenge)
        algorithm = params.get("algorithm", "SHA-256").upper()

        # Normalize algorithm name
        if algorithm in ["SHA256", "SHA-256"]:
            algorithm = "SHA-256"
        elif algorithm in ["SHA384", "SHA-384"]:
            algorithm = "SHA-384"
        elif algorithm in ["SHA512", "SHA-512"]:
            algorithm = "SHA-512"
        elif "PBKDF2" in algorithm:
            if "384" in algorithm:
                algorithm = "PBKDF2/SHA-384"
            elif "512" in algorithm:
                algorithm = "PBKDF2/SHA-512"
            else:
                algorithm = "PBKDF2/SHA-256"

        # Dispatch to appropriate solver
        if algorithm in ["SHA-256", "SHA-384", "SHA-512"]:
            if "challenge" in params:
                return self._solve_sha_challenge(params, algorithm)
            else:
                return self._solve_sha_prefix(params, algorithm)
        elif algorithm.startswith("PBKDF2"):
            return self._solve_pbkdf2(params, algorithm)
        elif algorithm == "ARGON2ID":
            return self._solve_argon2(params)
        elif algorithm == "SCRYPT":
            return self._solve_scrypt(params)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported: {self.SUPPORTED_ALGORITHMS}")

    def _solve_sha_challenge(self, params: Dict[str, Any], algorithm: str) -> Dict[str, Any]:
        """
        Solve SHA challenge by finding hash that matches challenge.

        This is the legacy Altcha format where:
            hash = SHA(salt + counter_string)
            valid if hash == challenge

        Args:
            params: Challenge parameters (salt, challenge, maxnumber)
            algorithm: SHA-256, SHA-384, or SHA-512

        Returns:
            Solution dict with counter, hash, time
        """
        salt = params["salt"]
        challenge = params["challenge"]
        max_number = params.get("maxnumber", self.max_iterations)
        hash_name = self.HASH_MAP[algorithm]

        start_time = time.time()

        for counter in range(min(max_number, self.max_iterations)):
            data = f"{salt}{counter}".encode('utf-8')
            hash_result = hashlib.new(hash_name, data).hexdigest()

            if hash_result == challenge:
                elapsed_ms = (time.time() - start_time) * 1000
                return {
                    "counter": counter,
                    "hash": hash_result,
                    "time": round(elapsed_ms, 1)
                }

        raise RuntimeError(f"No solution found after {min(max_number, self.max_iterations)} iterations")

    def _solve_sha_prefix(self, params: Dict[str, Any], algorithm: str) -> Dict[str, Any]:
        """
        Solve SHA challenge by finding hash that starts with prefix.

        Format:
            password = nonce_bytes + counter_bytes (4B big-endian)
            hash = SHA(password)
            valid if hash.hex().startswith(keyPrefix)

        Args:
            params: Challenge parameters (nonce, salt, keyPrefix)
            algorithm: SHA-256, SHA-384, or SHA-512

        Returns:
            Solution dict with counter, derivedKey, time
        """
        nonce = params.get("nonce", params.get("salt", ""))
        key_prefix = params.get("keyPrefix", "00")
        hash_name = self.HASH_MAP[algorithm]

        # Handle both hex and string nonces
        try:
            nonce_bytes = bytes.fromhex(nonce)
        except ValueError:
            nonce_bytes = nonce.encode('utf-8')

        start_time = time.time()

        for counter in range(self.max_iterations):
            password = nonce_bytes + counter.to_bytes(4, 'big')
            hash_result = hashlib.new(hash_name, password).hexdigest()

            if hash_result.startswith(key_prefix):
                elapsed_ms = (time.time() - start_time) * 1000
                return {
                    "counter": counter,
                    "derivedKey": hash_result,
                    "time": round(elapsed_ms, 1)
                }

        raise RuntimeError(f"No solution found after {self.max_iterations} iterations")

    def _solve_pbkdf2(self, params: Dict[str, Any], algorithm: str) -> Dict[str, Any]:
        """
        Solve PBKDF2 challenge.

        Algorithm:
            password = nonce_bytes (16B) + counter_bytes (4B big-endian)
            key = PBKDF2-HMAC-SHA256/384/512(password, salt, cost, keyLength)
            valid if key.hex().startswith(keyPrefix)

        Args:
            params: Challenge parameters containing:
                - nonce: 16-byte hex string
                - salt: 16-byte hex string
                - cost: PBKDF2 iterations
                - keyLength: Output key size in bytes
                - keyPrefix: Required hex prefix

        Returns:
            Solution dict with counter, derivedKey, time
        """
        nonce = params["nonce"]
        salt = params["salt"]
        cost = params["cost"]
        key_length = params.get("keyLength", self.KEY_LENGTHS[algorithm])
        key_prefix = params["keyPrefix"]
        hash_name = self.HASH_MAP[algorithm]

        nonce_bytes = bytes.fromhex(nonce)
        salt_bytes = bytes.fromhex(salt)

        start_time = time.time()

        for counter in range(self.max_iterations):
            # Password = nonce (16 bytes) + counter (4 bytes big-endian)
            password = nonce_bytes + counter.to_bytes(4, 'big')

            # Derive key using PBKDF2-HMAC
            key = hashlib.pbkdf2_hmac(
                hash_name,
                password,
                salt_bytes,
                cost,
                key_length
            )

            if key.hex().startswith(key_prefix):
                elapsed_ms = (time.time() - start_time) * 1000
                return {
                    "counter": counter,
                    "derivedKey": key.hex(),
                    "time": round(elapsed_ms, 1)
                }

        raise RuntimeError(f"No solution found after {self.max_iterations} iterations")

    def _solve_argon2(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Solve Argon2id challenge.

        Algorithm:
            password = nonce_bytes (16B) + counter_bytes (4B big-endian)
            key = Argon2id(password, salt, time_cost, memory_cost, parallelism, keyLength)
            valid if key.hex().startswith(keyPrefix)

        Requires: pip install argon2-cffi

        Args:
            params: Challenge parameters containing:
                - nonce: 16-byte hex string
                - salt: 16-byte hex string
                - cost: Time cost (iterations)
                - memoryCost: Memory cost in KB
                - parallelism: Parallelism factor
                - keyLength: Output key size
                - keyPrefix: Required hex prefix

        Returns:
            Solution dict with counter, derivedKey, time
        """
        if not ARGON2_AVAILABLE:
            raise ImportError(
                "Argon2 support requires argon2-cffi. Install with: pip install argon2-cffi"
            )

        nonce = params["nonce"]
        salt = params["salt"]
        time_cost = params.get("cost", 3)
        memory_cost = params.get("memoryCost", 65536)  # KB
        parallelism = params.get("parallelism", 1)
        key_length = params.get("keyLength", 32)
        key_prefix = params["keyPrefix"]

        nonce_bytes = bytes.fromhex(nonce)
        salt_bytes = bytes.fromhex(salt)

        start_time = time.time()

        for counter in range(self.max_iterations):
            password = nonce_bytes + counter.to_bytes(4, 'big')

            key = hash_secret_raw(
                secret=password,
                salt=salt_bytes,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=key_length,
                type=Type.ID
            )

            if key.hex().startswith(key_prefix):
                elapsed_ms = (time.time() - start_time) * 1000
                return {
                    "counter": counter,
                    "derivedKey": key.hex(),
                    "time": round(elapsed_ms, 1)
                }

        raise RuntimeError(f"No solution found after {self.max_iterations} iterations")

    def _solve_scrypt(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Solve Scrypt challenge.

        Algorithm:
            password = nonce_bytes (16B) + counter_bytes (4B big-endian)
            key = Scrypt(password, salt, n=cost, r=8, p=1, keyLength)
            valid if key.hex().startswith(keyPrefix)

        Args:
            params: Challenge parameters containing:
                - nonce: 16-byte hex string
                - salt: 16-byte hex string
                - cost: Scrypt N parameter (CPU/memory cost, power of 2)
                - memoryCost: Scrypt r parameter (block size, default 8)
                - parallelism: Scrypt p parameter (parallelism, default 1)
                - keyLength: Output key size
                - keyPrefix: Required hex prefix

        Returns:
            Solution dict with counter, derivedKey, time
        """
        nonce = params["nonce"]
        salt = params["salt"]
        n = params.get("cost", 16384)  # CPU/memory cost factor
        r = params.get("memoryCost", 8)  # Block size
        p = params.get("parallelism", 1)  # Parallelism
        key_length = params.get("keyLength", 32)
        key_prefix = params["keyPrefix"]

        nonce_bytes = bytes.fromhex(nonce)
        salt_bytes = bytes.fromhex(salt)

        start_time = time.time()

        for counter in range(self.max_iterations):
            password = nonce_bytes + counter.to_bytes(4, 'big')

            key = hashlib.scrypt(
                password,
                salt=salt_bytes,
                n=n,
                r=r,
                p=p,
                dklen=key_length
            )

            if key.hex().startswith(key_prefix):
                elapsed_ms = (time.time() - start_time) * 1000
                return {
                    "counter": counter,
                    "derivedKey": key.hex(),
                    "time": round(elapsed_ms, 1)
                }

        raise RuntimeError(f"No solution found after {self.max_iterations} iterations")

    def build_payload(
        self,
        challenge: Dict[str, Any],
        solution: Dict[str, Any]
    ) -> str:
        """
        Build base64-encoded payload for submission.

        Format:
            Base64({
                "challenge": { original challenge },
                "solution": { counter, derivedKey/hash, time }
            })

        Args:
            challenge: Original challenge from server
            solution: Solution from solve()

        Returns:
            Base64-encoded JSON string ready for submission
        """
        payload = {
            "challenge": challenge,
            "solution": solution
        }

        json_str = json.dumps(payload, separators=(',', ':'))
        return base64.b64encode(json_str.encode()).decode()

    def verify_solution(
        self,
        params: Dict[str, Any],
        solution: Dict[str, Any]
    ) -> bool:
        """
        Verify a solution is correct.

        Args:
            params: Challenge parameters
            solution: Solution to verify

        Returns:
            True if solution is valid, False otherwise
        """
        algorithm = params.get("algorithm", "SHA-256").upper()
        counter = solution["counter"]

        try:
            if algorithm.startswith("PBKDF2"):
                hash_name = self.HASH_MAP.get(algorithm, "sha256")
                nonce_bytes = bytes.fromhex(params["nonce"])
                salt_bytes = bytes.fromhex(params["salt"])
                password = nonce_bytes + counter.to_bytes(4, 'big')

                key = hashlib.pbkdf2_hmac(
                    hash_name,
                    password,
                    salt_bytes,
                    params["cost"],
                    params.get("keyLength", 32)
                )
                return key.hex().startswith(params["keyPrefix"])

            elif algorithm in ["SHA-256", "SHA-384", "SHA-512"]:
                if "challenge" in params:
                    data = f"{params['salt']}{counter}".encode('utf-8')
                    hash_result = hashlib.new(self.HASH_MAP[algorithm], data).hexdigest()
                    return hash_result == params["challenge"]
                else:
                    nonce_bytes = bytes.fromhex(params.get("nonce", params.get("salt")))
                    password = nonce_bytes + counter.to_bytes(4, 'big')
                    hash_result = hashlib.new(self.HASH_MAP[algorithm], password).hexdigest()
                    return hash_result.startswith(params["keyPrefix"])

            elif algorithm == "SCRYPT":
                nonce_bytes = bytes.fromhex(params["nonce"])
                salt_bytes = bytes.fromhex(params["salt"])
                password = nonce_bytes + counter.to_bytes(4, 'big')

                key = hashlib.scrypt(
                    password,
                    salt=salt_bytes,
                    n=params.get("cost", 16384),
                    r=params.get("memoryCost", 8),
                    p=params.get("parallelism", 1),
                    dklen=params.get("keyLength", 32)
                )
                return key.hex().startswith(params["keyPrefix"])

            elif algorithm == "ARGON2ID":
                if not ARGON2_AVAILABLE:
                    return False
                nonce_bytes = bytes.fromhex(params["nonce"])
                salt_bytes = bytes.fromhex(params["salt"])
                password = nonce_bytes + counter.to_bytes(4, 'big')

                key = hash_secret_raw(
                    secret=password,
                    salt=salt_bytes,
                    time_cost=params.get("cost", 3),
                    memory_cost=params.get("memoryCost", 65536),
                    parallelism=params.get("parallelism", 1),
                    hash_len=params.get("keyLength", 32),
                    type=Type.ID
                )
                return key.hex().startswith(params["keyPrefix"])

        except Exception:
            return False

        return False

    @staticmethod
    def list_algorithms() -> list:
        """Return list of supported algorithms."""
        return AltchaSolver.SUPPORTED_ALGORITHMS.copy()


def main():
    """Command-line interface."""
    parser = argparse.ArgumentParser(
        description="Altcha Proof-of-Work Solver - Supports all algorithm variants",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Algorithms:
  SHA-256, SHA-384, SHA-512       Hash matching (legacy)
  PBKDF2/SHA-256/384/512          Key derivation with iterations
  ARGON2ID                        Memory-hard (requires argon2-cffi)
  SCRYPT                          Memory-hard (native Python)

Examples:
  # PBKDF2 challenge
  python altcha_solver.py pbkdf2 \\
      --nonce "4db2e1ee6108476cba8972f39cf900b9" \\
      --salt "98b95a514955c35e73de9252423882a5" \\
      --cost 5000 --prefix "00"

  # Scrypt challenge
  python altcha_solver.py scrypt \\
      --nonce "4db2e1ee6108476cba8972f39cf900b9" \\
      --salt "98b95a514955c35e73de9252423882a5" \\
      --cost 16384 --prefix "00"

  # SHA-256 with challenge hash
  python altcha_solver.py sha256 \\
      --salt "randomsalt" \\
      --challenge "abc123def456..."
        """
    )

    subparsers = parser.add_subparsers(dest="algorithm", help="Algorithm type")

    # Common arguments for prefix-based algorithms
    def add_prefix_args(p):
        p.add_argument("--nonce", required=True, help="Nonce hex string (16 bytes)")
        p.add_argument("--salt", required=True, help="Salt hex string (16 bytes)")
        p.add_argument("--prefix", required=True, help="Key prefix to match")
        p.add_argument("--keylength", type=int, default=32, help="Key length in bytes")

    # PBKDF2 variants
    for variant in ["pbkdf2", "pbkdf2-384", "pbkdf2-512"]:
        p = subparsers.add_parser(variant, help=f"{variant.upper()} challenge")
        add_prefix_args(p)
        p.add_argument("--cost", type=int, required=True, help="PBKDF2 iterations")

    # Scrypt
    scrypt_parser = subparsers.add_parser("scrypt", help="Scrypt challenge")
    add_prefix_args(scrypt_parser)
    scrypt_parser.add_argument("--cost", type=int, default=16384, help="Scrypt N parameter")
    scrypt_parser.add_argument("--block-size", type=int, default=8, help="Scrypt r parameter")
    scrypt_parser.add_argument("--parallelism", type=int, default=1, help="Scrypt p parameter")

    # Argon2
    argon2_parser = subparsers.add_parser("argon2", help="Argon2id challenge")
    add_prefix_args(argon2_parser)
    argon2_parser.add_argument("--cost", type=int, default=3, help="Time cost")
    argon2_parser.add_argument("--memory", type=int, default=65536, help="Memory cost in KB")
    argon2_parser.add_argument("--parallelism", type=int, default=1, help="Parallelism")

    # SHA variants
    for variant in ["sha256", "sha384", "sha512"]:
        p = subparsers.add_parser(variant, help=f"{variant.upper()} challenge")
        p.add_argument("--salt", required=True, help="Salt string")
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument("--challenge", help="Expected hash (legacy mode)")
        group.add_argument("--prefix", help="Key prefix to match (modern mode)")
        p.add_argument("--nonce", help="Nonce (for prefix mode)")
        p.add_argument("--maxnumber", type=int, default=100000, help="Max counter")

    # Global options
    parser.add_argument("--json", help="Challenge as JSON string")
    parser.add_argument("--output", choices=["json", "text"], default="text", help="Output format")
    parser.add_argument("--list", action="store_true", help="List supported algorithms")

    args = parser.parse_args()

    if args.list:
        print("Supported algorithms:")
        for alg in AltchaSolver.SUPPORTED_ALGORITHMS:
            print(f"  - {alg}")
        return

    solver = AltchaSolver()

    # Handle JSON input
    if args.json:
        challenge = json.loads(args.json)
        solution = solver.solve(challenge)

    elif args.algorithm in ["pbkdf2", "pbkdf2-384", "pbkdf2-512"]:
        alg_map = {"pbkdf2": "PBKDF2/SHA-256", "pbkdf2-384": "PBKDF2/SHA-384", "pbkdf2-512": "PBKDF2/SHA-512"}
        challenge = {
            "parameters": {
                "algorithm": alg_map[args.algorithm],
                "nonce": args.nonce,
                "salt": args.salt,
                "cost": args.cost,
                "keyLength": args.keylength,
                "keyPrefix": args.prefix
            }
        }
        solution = solver.solve(challenge)

    elif args.algorithm == "scrypt":
        challenge = {
            "parameters": {
                "algorithm": "SCRYPT",
                "nonce": args.nonce,
                "salt": args.salt,
                "cost": args.cost,
                "memoryCost": args.block_size,
                "parallelism": args.parallelism,
                "keyLength": args.keylength,
                "keyPrefix": args.prefix
            }
        }
        solution = solver.solve(challenge)

    elif args.algorithm == "argon2":
        challenge = {
            "parameters": {
                "algorithm": "ARGON2ID",
                "nonce": args.nonce,
                "salt": args.salt,
                "cost": args.cost,
                "memoryCost": args.memory,
                "parallelism": args.parallelism,
                "keyLength": args.keylength,
                "keyPrefix": args.prefix
            }
        }
        solution = solver.solve(challenge)

    elif args.algorithm in ["sha256", "sha384", "sha512"]:
        alg_map = {"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
        if args.challenge:
            challenge = {
                "parameters": {
                    "algorithm": alg_map[args.algorithm],
                    "salt": args.salt,
                    "challenge": args.challenge,
                    "maxnumber": args.maxnumber
                }
            }
        else:
            challenge = {
                "parameters": {
                    "algorithm": alg_map[args.algorithm],
                    "nonce": args.nonce or args.salt,
                    "keyPrefix": args.prefix
                }
            }
        solution = solver.solve(challenge)

    else:
        parser.print_help()
        return

    # Output
    if args.output == "json":
        print(json.dumps({
            "solution": solution,
            "payload": solver.build_payload(challenge, solution)
        }, indent=2))
    else:
        print(f"Solution found!")
        print(f"  Algorithm: {challenge['parameters']['algorithm']}")
        print(f"  Counter:   {solution['counter']}")
        if "derivedKey" in solution:
            print(f"  Key:       {solution['derivedKey'][:48]}...")
        if "hash" in solution:
            print(f"  Hash:      {solution['hash'][:48]}...")
        print(f"  Time:      {solution['time']}ms")
        print()
        print(f"Base64 Payload:")
        payload = solver.build_payload(challenge, solution)
        print(f"  {payload[:80]}...")


if __name__ == "__main__":
    main()
