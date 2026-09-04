# Altcha Algorithm Technical Specification

Complete technical documentation for all 8 Altcha proof-of-work algorithm variants.

---

## Table of Contents

1. [Overview](#overview)
2. [Algorithm Summary](#algorithm-summary)
3. [Common Format](#common-format)
4. [PBKDF2 Variants](#pbkdf2-variants)
5. [SHA Variants](#sha-variants)
6. [Scrypt](#scrypt)
7. [Argon2id](#argon2id)
8. [Implementation Notes](#implementation-notes)
9. [Worked Examples](#worked-examples)

---

## Overview

Altcha uses proof-of-work (PoW) to deter automated abuse. The client must find a counter value that, when combined with server-provided parameters, produces a hash/key meeting specific criteria.

### Flow Diagram

```
┌─────────┐                              ┌─────────┐
│  Client │                              │  Server │
└────┬────┘                              └────┬────┘
     │                                        │
     │  1. GET /captcha                       │
     │ ─────────────────────────────────────► │
     │                                        │
     │  2. Challenge JSON                     │
     │ ◄───────────────────────────────────── │
     │     {algorithm, parameters, signature} │
     │                                        │
     │  3. Solve PoW                          │
     │  ┌─────────────────────────┐           │
     │  │ for counter in 0..N:    │           │
     │  │   key = KDF(counter)    │           │
     │  │   if valid(key): break  │           │
     │  └─────────────────────────┘           │
     │                                        │
     │  4. POST /submit                       │
     │     {data, captcha: base64(solution)}  │
     │ ─────────────────────────────────────► │
     │                                        │
     │  5. Verify & respond                   │
     │ ◄───────────────────────────────────── │
```

---

## Algorithm Summary

| Algorithm | Type | Complexity | Python Module |
|-----------|------|------------|---------------|
| SHA-256 | Hash | O(1) per iter | `hashlib` |
| SHA-384 | Hash | O(1) per iter | `hashlib` |
| SHA-512 | Hash | O(1) per iter | `hashlib` |
| PBKDF2/SHA-256 | KDF | O(cost) per iter | `hashlib.pbkdf2_hmac` |
| PBKDF2/SHA-384 | KDF | O(cost) per iter | `hashlib.pbkdf2_hmac` |
| PBKDF2/SHA-512 | KDF | O(cost) per iter | `hashlib.pbkdf2_hmac` |
| Scrypt | Memory-hard | O(N*r*p) per iter | `hashlib.scrypt` |
| Argon2id | Memory-hard | O(t*m*p) per iter | `argon2-cffi` |

---

## Common Format

### Password Construction

All algorithms use the same password format (20 bytes):

```
┌─────────────────────────────────────────────┐
│  Bytes 0-15:  nonce (from hex string)       │
│  Bytes 16-19: counter (4 bytes, big-endian) │
└─────────────────────────────────────────────┘
```

**Python:**
```python
nonce_bytes = bytes.fromhex(nonce)  # 16 bytes
counter_bytes = counter.to_bytes(4, 'big')  # 4 bytes
password = nonce_bytes + counter_bytes  # 20 bytes
```

**Example for counter = 494 (0x000001EE):**
```
nonce:    4d b2 e1 ee 61 08 47 6c ba 89 72 f3 9c f9 00 b9
counter:  00 00 01 ee
password: 4d b2 e1 ee 61 08 47 6c ba 89 72 f3 9c f9 00 b9 00 00 01 ee
```

### Challenge Structure

```json
{
  "parameters": {
    "algorithm": "PBKDF2/SHA-256",
    "nonce": "4db2e1ee6108476cba8972f39cf900b9",
    "salt": "98b95a514955c35e73de9252423882a5",
    "cost": 5000,
    "memoryCost": 0,
    "parallelism": 1,
    "keyLength": 32,
    "keyPrefix": "0051627a"
  },
  "signature": "7b2de5af270b98601e44236e1b54e1db7d3b6eed12f1d4790281d6b7f8ef34bb"
}
```

### Solution Structure

```json
{
  "counter": 494,
  "derivedKey": "0051627a347a5c8a312d85d0f1fd2a6c64fa334609495322ac54ca399c3e4aa1",
  "time": 1494.4
}
```

### Submission Payload

Base64-encoded JSON:
```json
{
  "challenge": { /* original challenge */ },
  "solution": { /* solution object */ }
}
```

---

## PBKDF2 Variants

### PBKDF2/SHA-256

The most common Altcha implementation.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `nonce` | hex (32 chars) | 16 random bytes |
| `salt` | hex (32 chars) | 16 random bytes |
| `cost` | integer | Iterations (2000-10000) |
| `keyLength` | integer | Output size (32 bytes) |
| `keyPrefix` | hex | Required prefix |

**Algorithm:**
```python
def solve_pbkdf2_sha256(nonce, salt, cost, keyLength, keyPrefix):
    nonce_bytes = bytes.fromhex(nonce)
    salt_bytes = bytes.fromhex(salt)
    
    for counter in range(MAX_ITERATIONS):
        password = nonce_bytes + counter.to_bytes(4, 'big')
        key = hashlib.pbkdf2_hmac('sha256', password, salt_bytes, cost, keyLength)
        
        if key.hex().startswith(keyPrefix):
            return {"counter": counter, "derivedKey": key.hex()}
```

### PBKDF2/SHA-384

Same as SHA-256 but with 384-bit hash.

**Differences:**
- `keyLength`: 48 bytes (default)
- Hash: SHA-384

### PBKDF2/SHA-512

Same as SHA-256 but with 512-bit hash.

**Differences:**
- `keyLength`: 64 bytes (default)
- Hash: SHA-512

---

## SHA Variants

### Legacy Mode (Challenge Matching)

For backwards compatibility with older implementations.

```python
def solve_sha_legacy(salt, challenge, maxnumber):
    for counter in range(maxnumber):
        data = f"{salt}{counter}".encode('utf-8')
        hash_result = hashlib.sha256(data).hexdigest()
        
        if hash_result == challenge:
            return {"counter": counter, "hash": hash_result}
```

### Modern Mode (Prefix Matching)

Same password format as PBKDF2.

```python
def solve_sha_modern(nonce, keyPrefix):
    nonce_bytes = bytes.fromhex(nonce)
    
    for counter in range(MAX_ITERATIONS):
        password = nonce_bytes + counter.to_bytes(4, 'big')
        hash_result = hashlib.sha256(password).hexdigest()
        
        if hash_result.startswith(keyPrefix):
            return {"counter": counter, "derivedKey": hash_result}
```

### SHA-384 and SHA-512

Same algorithms, different hash functions:
- SHA-384: 96-char hex output
- SHA-512: 128-char hex output

---

## Scrypt

Memory-hard key derivation function. Native in Python 3.6+.

**Parameters:**
| Name | Parameter | Description | Default |
|------|-----------|-------------|---------|
| `cost` | N | CPU/memory cost (power of 2) | 16384 |
| `memoryCost` | r | Block size | 8 |
| `parallelism` | p | Parallelization | 1 |
| `keyLength` | dklen | Output size | 32 |

**Algorithm:**
```python
def solve_scrypt(nonce, salt, cost, memoryCost, parallelism, keyLength, keyPrefix):
    nonce_bytes = bytes.fromhex(nonce)
    salt_bytes = bytes.fromhex(salt)
    
    for counter in range(MAX_ITERATIONS):
        password = nonce_bytes + counter.to_bytes(4, 'big')
        
        key = hashlib.scrypt(
            password,
            salt=salt_bytes,
            n=cost,         # N parameter
            r=memoryCost,   # r parameter
            p=parallelism,  # p parameter
            dklen=keyLength
        )
        
        if key.hex().startswith(keyPrefix):
            return {"counter": counter, "derivedKey": key.hex()}
```

**Memory Usage:**
```
Memory = 128 * N * r bytes
Example: 128 * 16384 * 8 = 16 MB
```

---

## Argon2id

Modern memory-hard KDF. Requires `argon2-cffi` package.

**Parameters:**
| Name | Description | Default |
|------|-------------|---------|
| `cost` | Time cost (iterations) | 3 |
| `memoryCost` | Memory in KB | 65536 |
| `parallelism` | Threads | 1 |
| `keyLength` | Output size | 32 |

**Algorithm:**
```python
from argon2.low_level import hash_secret_raw, Type

def solve_argon2(nonce, salt, cost, memoryCost, parallelism, keyLength, keyPrefix):
    nonce_bytes = bytes.fromhex(nonce)
    salt_bytes = bytes.fromhex(salt)
    
    for counter in range(MAX_ITERATIONS):
        password = nonce_bytes + counter.to_bytes(4, 'big')
        
        key = hash_secret_raw(
            secret=password,
            salt=salt_bytes,
            time_cost=cost,
            memory_cost=memoryCost,
            parallelism=parallelism,
            hash_len=keyLength,
            type=Type.ID  # Argon2id
        )
        
        if key.hex().startswith(keyPrefix):
            return {"counter": counter, "derivedKey": key.hex()}
```

---

## Implementation Notes

### Common Mistakes

1. **Wrong password format**
   ```python
   # WRONG - string concatenation
   password = f"{nonce}{counter}".encode()
   
   # CORRECT - bytes concatenation
   password = bytes.fromhex(nonce) + counter.to_bytes(4, 'big')
   ```

2. **Wrong endianness**
   ```python
   # WRONG - little endian
   counter.to_bytes(4, 'little')
   
   # CORRECT - big endian
   counter.to_bytes(4, 'big')
   ```

3. **Wrong counter size**
   ```python
   # WRONG - 8 bytes
   counter.to_bytes(8, 'big')
   
   # CORRECT - 4 bytes
   counter.to_bytes(4, 'big')
   ```

### Prefix Length and Solutions

| Prefix Length | Hex Chars | Avg Iterations | Uniqueness |
|---------------|-----------|----------------|------------|
| 1 byte | 2 | ~256 | Multiple |
| 2 bytes | 4 | ~65,536 | Few |
| 4 bytes | 8 | ~4 billion | Usually unique |
| 8 bytes | 16 | Exactly 1 | Always unique |

### Performance Characteristics

| Algorithm | Cost | Time per Iteration |
|-----------|------|-------------------|
| SHA-256 | - | ~2 μs |
| PBKDF2 | 2000 | ~1.3 ms |
| PBKDF2 | 5000 | ~3 ms |
| Scrypt | N=16384 | ~70 ms |
| Argon2 | t=3, m=64MB | ~300 ms |

---

## Worked Examples

### Example 1: PBKDF2/SHA-256

**Input:**
```
nonce:     4db2e1ee6108476cba8972f39cf900b9
salt:      98b95a514955c35e73de9252423882a5
cost:      5000
keyLength: 32
keyPrefix: 00
```

**Process:**
```
counter=0:   password=4db2e1ee...00000000 → key=a1b2c3... (no match)
counter=1:   password=4db2e1ee...00000001 → key=f4e5d6... (no match)
...
counter=491: password=4db2e1ee...000001eb → key=001a40bc... (MATCH!)
```

**Output:**
```json
{
  "counter": 491,
  "derivedKey": "001a40bc17ec10e1fac274d69107e24666e2ebb03cb919c0c8d260e417d9f125"
}
```

### Example 2: Scrypt

**Input:**
```
nonce:       4db2e1ee6108476cba8972f39cf900b9
salt:        98b95a514955c35e73de9252423882a5
cost:        1024 (N)
memoryCost:  8 (r)
parallelism: 1 (p)
keyLength:   32
keyPrefix:   0
```

**Output:**
```json
{
  "counter": 12,
  "derivedKey": "0f251ffd6afae0e2ba06b5737c5e8c86..."
}
```

### Example 3: Multiple Valid Solutions

For short prefix "00" with PBKDF2/SHA-256 (cost=2000):

```
counter=455: key=0057b804... ✓
counter=946: key=0089a2bc... ✓
```

Both are valid solutions. The solver returns the first one found.

---

## References

- [Altcha Source Code](https://github.com/altcha-org/altcha)
- [PBKDF2 RFC 2898](https://tools.ietf.org/html/rfc2898)
- [Scrypt RFC 7914](https://tools.ietf.org/html/rfc7914)
- [Argon2 RFC 9106](https://tools.ietf.org/html/rfc9106)
- [Altcha Playground](https://playground.altcha.org)
