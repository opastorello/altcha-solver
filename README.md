# Altcha Solver

[![CI](https://github.com/opastorello/altcha-solver/actions/workflows/ci.yml/badge.svg)](https://github.com/opastorello/altcha-solver/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/altcha-solver.svg)](https://pypi.org/project/altcha-solver/)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Universal proof-of-work CAPTCHA solver for [Altcha](https://altcha.org/) - supports ALL algorithm variants.**

Altcha is an open-source, privacy-focused CAPTCHA alternative that uses proof-of-work (PoW) instead of image recognition. This solver implements all 8 supported algorithms, allowing you to solve any Altcha challenge programmatically.

---

## Table of Contents

- [Features](#features)
- [Supported Algorithms](#supported-algorithms)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Python Library](#python-library)
  - [Command Line](#command-line)
- [Algorithm Reference](#algorithm-reference)
  - [PBKDF2 Variants](#pbkdf2-variants)
  - [SHA Variants](#sha-variants)
  - [Scrypt](#scrypt)
  - [Argon2id](#argon2id)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Performance](#performance)
- [How It Works](#how-it-works)
- [Testing](#testing)
- [License](#license)

---

## Features

- **Universal Compatibility**: Supports all 8 Altcha algorithm variants
- **Zero Dependencies**: Core functionality uses Python standard library only
- **Battle-Tested**: Validated against official [Altcha Playground](https://playground.altcha.org)
- **Production Ready**: Includes parallel processing, verification, and payload encoding
- **Well Documented**: Complete algorithm specifications and examples

---

## Supported Algorithms

| Algorithm | Type | Python Support | Description |
|-----------|------|----------------|-------------|
| **SHA-256** | Hash | Native | Simple hash matching |
| **SHA-384** | Hash | Native | 384-bit hash matching |
| **SHA-512** | Hash | Native | 512-bit hash matching |
| **PBKDF2/SHA-256** | KDF | Native | Key derivation, 256-bit |
| **PBKDF2/SHA-384** | KDF | Native | Key derivation, 384-bit |
| **PBKDF2/SHA-512** | KDF | Native | Key derivation, 512-bit |
| **Scrypt** | Memory-hard | Native (3.6+) | Memory-hard KDF |
| **Argon2id** | Memory-hard | Requires `argon2-cffi` | Modern memory-hard KDF |

---

## Installation

### From PyPI (Recommended)

```bash
pip install altcha-solver

# With Argon2 support
pip install altcha-solver[argon2]
```

### From Source

```bash
git clone https://github.com/opastorello/altcha-solver.git
cd altcha-solver
pip install .

# Or install in development mode
pip install -e .[dev]
```

**Requirements:** Python 3.6+

---

## Quick Start

```python
from altcha_solver import AltchaSolver

# Create solver
solver = AltchaSolver()

# Solve any Altcha challenge
challenge = {
    "parameters": {
        "algorithm": "PBKDF2/SHA-256",
        "nonce": "4db2e1ee6108476cba8972f39cf900b9",
        "salt": "98b95a514955c35e73de9252423882a5",
        "cost": 5000,
        "keyLength": 32,
        "keyPrefix": "00"
    }
}

solution = solver.solve(challenge)
print(f"Counter: {solution['counter']}")
print(f"Key: {solution['derivedKey']}")

# Build submission payload
payload = solver.build_payload(challenge, solution)
```

---

## Usage

### Python Library

```python
from altcha_solver import AltchaSolver

solver = AltchaSolver(max_iterations=100000)

# Automatic algorithm detection
solution = solver.solve(challenge)

# Verify solution
is_valid = solver.verify_solution(challenge["parameters"], solution)

# Build base64 payload for submission
payload = solver.build_payload(challenge, solution)

# List supported algorithms
algorithms = solver.list_algorithms()
```

### Command Line

```bash
# PBKDF2/SHA-256
python altcha_solver.py pbkdf2 \
    --nonce "4db2e1ee6108476cba8972f39cf900b9" \
    --salt "98b95a514955c35e73de9252423882a5" \
    --cost 5000 --prefix "00"

# PBKDF2/SHA-384
python altcha_solver.py pbkdf2-384 \
    --nonce "4db2e1ee6108476cba8972f39cf900b9" \
    --salt "98b95a514955c35e73de9252423882a5" \
    --cost 5000 --prefix "00"

# Scrypt
python altcha_solver.py scrypt \
    --nonce "4db2e1ee6108476cba8972f39cf900b9" \
    --salt "98b95a514955c35e73de9252423882a5" \
    --cost 16384 --prefix "00"

# Argon2id (requires argon2-cffi)
python altcha_solver.py argon2 \
    --nonce "4db2e1ee6108476cba8972f39cf900b9" \
    --salt "98b95a514955c35e73de9252423882a5" \
    --cost 3 --memory 65536 --prefix "00"

# SHA-256 (legacy mode)
python altcha_solver.py sha256 \
    --salt "randomsalt" \
    --challenge "expected_hash_here"

# JSON output
python altcha_solver.py pbkdf2 --nonce ... --output json

# List algorithms
python altcha_solver.py --list
```

---

## Algorithm Reference

### PBKDF2 Variants

The most common Altcha implementation. Uses Password-Based Key Derivation Function 2.

**Challenge Structure:**
```json
{
  "parameters": {
    "algorithm": "PBKDF2/SHA-256",
    "nonce": "4db2e1ee6108476cba8972f39cf900b9",
    "salt": "98b95a514955c35e73de9252423882a5",
    "cost": 5000,
    "keyLength": 32,
    "keyPrefix": "0051627a347a5c8a",
    "memoryCost": 0
  },
  "signature": "7b2de5af..."
}
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `algorithm` | string | `PBKDF2/SHA-256`, `PBKDF2/SHA-384`, or `PBKDF2/SHA-512` |
| `nonce` | hex string | 16 random bytes (32 hex chars) |
| `salt` | hex string | 16 random bytes (32 hex chars) |
| `cost` | integer | PBKDF2 iterations (typically 2000-10000) |
| `keyLength` | integer | Output key size in bytes (32, 48, or 64) |
| `keyPrefix` | hex string | Required prefix of derived key |
| `signature` | hex string | HMAC for server verification |

**Algorithm:**
```
FOR counter FROM 0 TO MAX:
    password = nonce_bytes (16B) + counter_bytes (4B big-endian)
    key = PBKDF2-HMAC-SHA256(password, salt_bytes, cost, keyLength)
    IF key.hex().startswith(keyPrefix):
        RETURN {counter, key}
```

### SHA Variants

Legacy format using simple hash matching.

**Mode 1: Challenge Matching**
```
hash = SHA256(salt_string + counter_string)
valid if hash == challenge
```

**Mode 2: Prefix Matching**
```
hash = SHA256(nonce_bytes + counter_bytes)
valid if hash.hex().startswith(keyPrefix)
```

### Scrypt

Memory-hard key derivation function. Native in Python 3.6+.

**Parameters:**
| Parameter | Description | Typical Value |
|-----------|-------------|---------------|
| `cost` | N parameter (CPU/memory) | 16384 |
| `memoryCost` | r parameter (block size) | 8 |
| `parallelism` | p parameter | 1 |

**Algorithm:**
```
password = nonce_bytes + counter_bytes
key = scrypt(password, salt, N=cost, r=memoryCost, p=parallelism)
valid if key.hex().startswith(keyPrefix)
```

### Argon2id

Modern memory-hard KDF. Requires `argon2-cffi` package.

**Parameters:**
| Parameter | Description | Typical Value |
|-----------|-------------|---------------|
| `cost` | Time cost (iterations) | 3 |
| `memoryCost` | Memory in KB | 65536 |
| `parallelism` | Parallel threads | 1 |

**Algorithm:**
```
password = nonce_bytes + counter_bytes
key = argon2id(password, salt, time=cost, memory=memoryCost, parallelism)
valid if key.hex().startswith(keyPrefix)
```

---

## API Reference

### `AltchaSolver`

```python
class AltchaSolver:
    def __init__(self, max_iterations: int = 100000):
        """Initialize solver with maximum iteration limit."""

    def solve(self, challenge: dict) -> dict:
        """
        Solve any Altcha challenge.

        Args:
            challenge: Challenge dict with 'parameters' key

        Returns:
            Solution dict with 'counter', 'derivedKey'/'hash', 'time'

        Raises:
            ValueError: Unsupported algorithm
            RuntimeError: No solution found
        """

    def verify_solution(self, params: dict, solution: dict) -> bool:
        """Verify a solution is correct."""

    def build_payload(self, challenge: dict, solution: dict) -> str:
        """Build base64-encoded submission payload."""

    @staticmethod
    def list_algorithms() -> list:
        """Return list of supported algorithm names."""
```

### Solution Format

```python
{
    "counter": 491,           # Found counter value
    "derivedKey": "001a40..", # Derived key (PBKDF2/Scrypt/Argon2)
    "hash": "abc123...",      # Hash (SHA variants)
    "time": 1494.4            # Solving time in milliseconds
}
```

### Payload Format

The submission payload is base64-encoded JSON:
```json
{
  "challenge": { /* original challenge */ },
  "solution": {
    "counter": 491,
    "derivedKey": "001a40bc...",
    "time": 1494.4
  }
}
```

---

## Examples

### Example 1: Basic PBKDF2

```python
from altcha_solver import AltchaSolver

solver = AltchaSolver()

# Challenge from Altcha Playground
challenge = {
    "parameters": {
        "algorithm": "PBKDF2/SHA-256",
        "nonce": "4db2e1ee6108476cba8972f39cf900b9",
        "salt": "98b95a514955c35e73de9252423882a5",
        "cost": 5000,
        "keyLength": 32,
        "keyPrefix": "00"
    }
}

solution = solver.solve(challenge)
# Output: counter=491, derivedKey=001a40bc...
```

### Example 2: Parallel Batch Processing

```python
from concurrent.futures import ThreadPoolExecutor
from altcha_solver import AltchaSolver

def solve_one(challenge):
    return AltchaSolver().solve(challenge)

# Pre-fetch challenges from server
challenges = [fetch_challenge() for _ in range(100)]

# Solve in parallel
with ThreadPoolExecutor(max_workers=20) as executor:
    solutions = list(executor.map(solve_one, challenges))

# 100 solved captchas ready to use
```

### Example 3: Full HTTP Flow

```python
import requests
from altcha_solver import AltchaSolver

# 1. Get challenge
response = requests.get("https://example.com/api/captcha")
challenge = response.json()

# 2. Solve
solver = AltchaSolver()
solution = solver.solve(challenge)

# 3. Build payload
payload = solver.build_payload(challenge, solution)

# 4. Submit
requests.post("https://example.com/api/action", json={
    "data": "your_data",
    "captcha": payload
})
```

### Example 4: All Algorithms

```python
from altcha_solver import AltchaSolver

solver = AltchaSolver()

# PBKDF2/SHA-256
solver.solve({"parameters": {"algorithm": "PBKDF2/SHA-256", ...}})

# PBKDF2/SHA-384
solver.solve({"parameters": {"algorithm": "PBKDF2/SHA-384", ...}})

# PBKDF2/SHA-512
solver.solve({"parameters": {"algorithm": "PBKDF2/SHA-512", ...}})

# Scrypt
solver.solve({"parameters": {"algorithm": "SCRYPT", ...}})

# Argon2id (requires argon2-cffi)
solver.solve({"parameters": {"algorithm": "ARGON2ID", ...}})

# SHA-256
solver.solve({"parameters": {"algorithm": "SHA-256", ...}})

# SHA-384
solver.solve({"parameters": {"algorithm": "SHA-384", ...}})

# SHA-512
solver.solve({"parameters": {"algorithm": "SHA-512", ...}})
```

---

## Performance

**Benchmark Results** (prefix="00", single thread):

| Algorithm | Parameters | Counter Found | Solve Time | Dependency |
|-----------|------------|---------------|------------|------------|
| **SHA-256** | - | 96 | 0.2 ms | Native |
| **SHA-384** | - | 217 | 0.4 ms | Native |
| **SHA-512** | - | 1119 | 1.8 ms | Native |
| **PBKDF2/SHA-256** | cost=2000 | 455 | 585 ms | Native |
| **PBKDF2/SHA-384** | cost=2000 | 182 | 355 ms | Native |
| **PBKDF2/SHA-512** | cost=2000 | 543 | 1038 ms | Native |
| **Scrypt** | N=1024, r=8 | 12 | 50 ms | Native |
| **Argon2id** | t=2, m=1024 | 3 | 5 ms | argon2-cffi |

**Iterations per Second** (approximate):

| Algorithm | Cost | Iter/sec |
|-----------|------|----------|
| SHA-256 | - | ~500,000 |
| SHA-384 | - | ~400,000 |
| SHA-512 | - | ~350,000 |
| PBKDF2/SHA-256 | 2000 | ~780 |
| PBKDF2/SHA-256 | 5000 | ~330 |
| Scrypt | N=16384 | ~15 |
| Argon2id | t=3, m=64MB | ~3 |

**Optimization Tips:**

1. **Lower cost = faster**: `cost=2000` is 2.5x faster than `cost=5000`
2. **Short prefix = faster**: Prefix "00" finds solution in ~256 iterations on average
3. **Parallel solving**: Pre-compute challenges in parallel threads
4. **Batch requests**: Fetch next challenge while solving current one

---

## How It Works

### Proof-of-Work Concept

Altcha uses computational puzzles instead of human verification:

1. **Server generates challenge** with random parameters
2. **Client computes** by iterating counter values
3. **Client finds solution** when derived key matches criteria
4. **Server verifies** the solution matches expected result

### Password Construction

All algorithms use the same password format:

```
┌─────────────────────────────────────────────┐
│  Bytes 0-15:  nonce (from hex string)       │
│  Bytes 16-19: counter (4 bytes, big-endian) │
└─────────────────────────────────────────────┘

Example for counter = 494 (0x000001EE):
  nonce:    4d b2 e1 ee 61 08 47 6c ba 89 72 f3 9c f9 00 b9
  counter:  00 00 01 ee
  password: 4d b2 e1 ee 61 08 47 6c ba 89 72 f3 9c f9 00 b9 00 00 01 ee
```

### Prefix Length and Solutions

| Prefix Length | Hex Chars | Avg Iterations | Uniqueness |
|---------------|-----------|----------------|------------|
| 1 byte | 2 ("00") | 256 | Multiple solutions |
| 2 bytes | 4 | 65,536 | Few solutions |
| 4 bytes | 8 | 4 billion+ | Usually unique |
| 8+ bytes | 16+ | Exactly 1 | Always unique |

---

## Testing

Run the test suite:

```bash
# Verify all algorithms
python examples/verify_algorithm.py

# Performance benchmark
python examples/benchmark.py

# Basic usage
python examples/basic_usage.py

# Batch processing
python examples/batch_solver.py
```

Expected output:
```
============================================================
ALTCHA ALGORITHM VERIFICATION
============================================================

Test 1: PBKDF2 with short prefix
  Counter:     491
  Verified:    PASS

Test 2: PBKDF2 with exact counter verification
  Target:      1234
  Found:       1234
  Verified:    PASS

Test 3: Multiple valid solutions for short prefix
  Valid:       [491, 494, 903]
  Verified:    PASS

Test 4: Solution verification
  Valid check:   PASS
  Invalid check: PASS

============================================================
RESULTS: 4 passed, 0 failed
============================================================
```

---

## Validation

This solver has been validated against:

- [Altcha Playground](https://playground.altcha.org) - Official testing environment
- [Altcha Source Code](https://github.com/altcha-org/altcha) - Reference implementation
- [Altcha Documentation](https://altcha.org/docs) - Official specs

---

## Limitations

- **Not a bypass**: PoW is designed to be solvable by any computer
- **Rate limiting**: Servers may implement additional rate limits
- **Challenge expiration**: Challenges typically expire after 2-5 minutes
- **Signature verification**: Server validates challenge wasn't tampered

---

## Security Considerations

**What Altcha provides:**
- Bot deterrence through computational cost
- Privacy (no tracking/fingerprinting)
- Accessibility (no visual challenges)

**What Altcha does NOT provide:**
- Human verification
- Strong bot prevention (determined attackers can parallelize)

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## References

- [Altcha Official Website](https://altcha.org)
- [Altcha Documentation](https://altcha.org/docs)
- [Altcha GitHub](https://github.com/altcha-org/altcha)
- [Altcha Playground](https://playground.altcha.org)
- [PBKDF2 RFC 2898](https://tools.ietf.org/html/rfc2898)
- [Scrypt RFC 7914](https://tools.ietf.org/html/rfc7914)
- [Argon2 RFC 9106](https://tools.ietf.org/html/rfc9106)
