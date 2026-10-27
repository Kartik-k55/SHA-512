# IMPLEMENTATION OF SHA-512 HASH FUNCTION
### Cryptography Mini Project & Interactive Educational Suite

---

## 1. Project Title
**IMPLEMENTATION OF SHA-512 HASH FUNCTION**  
*A College-Level Cryptography and Network Security Demonstration Project*

---

## 2. Introduction
In modern digital communication, data integrity and authentication are vital pillars of cybersecurity. Cryptographic hash functions transform arbitrary-sized messages into fixed-size mathematical digests. Among cryptographic hashing algorithms, **SHA-512** (Secure Hash Algorithm 512-bit) stands as one of the most robust, collision-resistant, and widely trusted hashing standards defined by the National Institute of Standards and Technology (**NIST FIPS PUB 180-4**) and the Internet Engineering Task Force (**RFC 6234**).

This project presents an educational, interactive web application that implements the complete SHA-512 algorithm entirely from scratch in pure Vanilla JavaScript using native 64-bit `BigInt` arithmetic modulo $2^{64}$.

---

## 3. Problem Statement
Many web applications rely on opaque cryptographic libraries (such as browser `crypto.subtle` or third-party packages) which hide internal mathematical operations, padding structures, and round transformations. Students and cybersecurity researchers often lack an accessible, transparent, visual tool that illustrates:
1. How messages are padded and partitioned into 1024-bit blocks.
2. How 64-bit words and the 80-round message schedule ($W_0 \dots W_{79}$) are derived.
3. How non-linear bitwise functions ($\text{Ch}, \text{Maj}, \Sigma_0, \Sigma_1, \sigma_0, \sigma_1$) drive the Davies-Meyer compression function.
4. How the **Avalanche Effect** operates at the exact bit and hexadecimal level.
5. How a manual algorithm can be verified against formal cryptographic test standards.

---

## 4. Objectives
The core objectives of this mini project are:
* **Manual Implementation**: Implement the complete NIST FIPS 180-4 SHA-512 standard in pure Vanilla JavaScript (`sha512.js`) without external dependencies or pre-built hashing frameworks.
* **Hash Generation**: Allow users to enter arbitrary text and compute its exact 512-bit digest (128 hexadecimal characters).
* **Integrity Verification**: Provide a verification tool to compare messages against expected 128-character hashes with format validation.
* **Avalanche Demonstration**: Quantify and visualize the strict avalanche criterion by comparing two slightly different inputs and computing flipped bits and hexadecimal variation.
* **Educational Architecture**: Provide comprehensive visual walkthroughs of the 8 algorithm steps and an interactive 64-bit logical function playground.
* **Automated Correctness Benchmark**: Verify our manual engine against the browser's native Web Crypto API and official NIST test vectors.

---

## 5. Technologies Used
* **HTML5**: Semantic document structure, accessible input forms, responsive layout containers, and math markup.
* **CSS3**: Modern dark mode aesthetic, glassmorphism (`backdrop-filter: blur()`), custom CSS grid/flexbox layouts, responsive typography, and neon cryptographic indicators.
* **Vanilla JavaScript (ES6+)**:
  * Native 64-bit `BigInt` operations for unsigned arithmetic modulo $2^{64}$ (`MASK_64 = 0xFFFFFFFFFFFFFFFFn`).
  * `TextEncoder` & typed byte arrays (`Uint8Array`, `DataView`) for strict binary operations.
  * Zero external libraries, frameworks, or cloud dependencies.
* **Web Crypto API (`crypto.subtle.digest`)**: Used exclusively as an automated test oracle to mathematically verify the manual implementation.

---

## 6. What is SHA-512?
**SHA-512** is a member of the **SHA-2** (Secure Hash Algorithm 2) family, designed by the United States National Security Agency (NSA) and published by NIST in 2002 (FIPS PUB 180-2, updated in FIPS PUB 180-4).

It is a **one-way cryptographic hash function** that accepts an input message of arbitrary length ($< 2^{128}$ bits) and outputs a unique, fixed-size **512-bit** message digest represented as **128 hexadecimal characters**.

> **Important Clarification:** SHA-512 is a **cryptographic hash function**, *not* an encryption algorithm. Encryption is a reversible two-way function requiring a key to decrypt ciphertext back to plaintext. Hashing is an irreversible, one-way mathematical transformation.

---

## 7. SHA-512 Characteristics

| Characteristic | Specification |
| :--- | :--- |
| **Algorithm Family** | SHA-2 (Secure Hash Algorithm 2) |
| **Output Hash Size** | 512 bits (64 bytes) |
| **Hexadecimal String Length** | 128 characters |
| **Input Block Size** | 1024 bits (128 bytes / 16 words) |
| **Word Size** | 64 bits (Unsigned BigInt) |
| **Number of Processing Rounds** | 80 compression rounds per 1024-bit block |
| **Max Message Length** | $< 2^{128}$ bits |
| **Collision Resistance** | $2^{256}$ operations |
| **Pre-image Resistance** | $2^{512}$ operations |
| **Underlying Construction** | Merkle–Damgård construction with Davies–Meyer compression |

---

## 8. Working Principle
SHA-512 operates on the principle of iterative block compression:
1. The arbitrary message is padded and divided into equal-sized **1024-bit blocks** ($M^{(1)}, M^{(2)}, \dots, M^{(N)}$).
2. An initial 512-bit state vector $H^{(0)}$ (consisting of eight 64-bit words $H_0 \dots H_7$) is initialized with predefined cryptographic constants.
3. Each block is fed sequentially into an **80-round compression function** along with the current state $H^{(i-1)}$ to produce the updated state $H^{(i)}$.
4. After processing the final block $M^{(N)}$, the values $H_0^{(N)} \dots H_7^{(N)}$ are concatenated into the final 128-hex-character digest.

---

## 9. Algorithm Steps

```
+-------------------------------------------------------+
|                    Input Message                      |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|             Step 1: UTF-8 Byte Encoding               |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|             Step 2: Append '1' Bit (0x80)             |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|            Step 3: Pad with k Zero Bytes              |
|        (Total length = 112 mod 128 bytes)             |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|         Step 4: Append 128-bit Message Length         |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|      Step 5: Partition into 1024-bit Blocks           |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|     Step 6: Expand Message Schedule W[0..79]          |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|       Step 7: Execute 80 Compression Rounds           |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|   Step 8: Update State & Generate 512-bit Digest      |
+-------------------------------------------------------+
```

---

## 10. Message Padding
To ensure the input length is an exact multiple of 1024 bits (128 bytes):
1. Suppose the original message has length $L$ bits ($L/8$ bytes).
2. Append a single bit `1` (represented as the byte `0x80`).
3. Append $k$ zero bits (`0x00` bytes) such that:
   $$(L + 1 + k) \equiv 896 \pmod{1024} \quad \text{or in bytes:} \quad (\text{bytes} + 1 + k_{\text{bytes}}) \equiv 112 \pmod{128}$$
4. Append the original message length $L$ as a **128-bit big-endian integer** (16 bytes).

The total length of the padded message is always a positive multiple of 1024 bits (128 bytes).

---

## 11. Message Schedule ($W_0 \dots W_{79}$)
For each 1024-bit block, 80 64-bit words are generated:
* For $t = 0 \dots 15$:
  $$W_t = M_t \quad \text{(the 16 successive 64-bit words of the current block)}$$
* For $t = 16 \dots 79$:
  $$W_t = \sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16} \pmod{2^{64}}$$

Where:
$$\sigma_0(x) = \text{ROTR}^{1}(x) \oplus \text{ROTR}^{8}(x) \oplus \text{SHR}^{7}(x)$$
$$\sigma_1(x) = \text{ROTR}^{19}(x) \oplus \text{ROTR}^{61}(x) \oplus \text{SHR}^{6}(x)$$

---

## 12. Compression Function
The compression function maintains eight 64-bit working registers $(a, b, c, d, e, f, g, h)$ initialized to the previous block's hash values $(H_0, H_1, \dots, H_7)$.

For each of the 80 rounds ($t = 0 \dots 79$):
$$T_1 = \left(h + \Sigma_1(e) + \text{Ch}(e, f, g) + K_t + W_t\right) \pmod{2^{64}}$$
$$T_2 = \left(\Sigma_0(a) + \text{Maj}(a, b, c)\right) \pmod{2^{64}}$$
$$h = g, \quad g = f, \quad f = e, \quad e = (d + T_1) \pmod{2^{64}}$$
$$d = c, \quad c = b, \quad b = a, \quad a = (T_1 + T_2) \pmod{2^{64}}$$

Where the non-linear boolean functions are:
* **Choose Function**: $\text{Ch}(x, y, z) = (x \land y) \oplus (\neg x \land z)$
* **Majority Function**: $\text{Maj}(x, y, z) = (x \land y) \oplus (x \land z) \oplus (y \land z)$
* **Big Sigma 0**: $\Sigma_0(x) = \text{ROTR}^{28}(x) \oplus \text{ROTR}^{34}(x) \oplus \text{ROTR}^{39}(x)$
* **Big Sigma 1**: $\Sigma_1(x) = \text{ROTR}^{14}(x) \oplus \text{ROTR}^{18}(x) \oplus \text{ROTR}^{41}(x)$

---

## 13. 80 Rounds
Each block undergoes 80 rounds of state transformation. In each round $t$, a unique round constant $K_t$ is injected. The 80 constants $K_0 \dots K_{79}$ are derived from the first 64 bits of the fractional parts of the cube roots of the first 80 prime numbers ($2 \dots 409$).

This constant injection introduces asymmetry and ensures that every round performs a distinct non-linear permutation.

---

## 14. Hash Generation
After 80 rounds, the working variables are added to the intermediate hash state:
$$H_0 = (H_0 + a) \pmod{2^{64}}$$
$$H_1 = (H_1 + b) \pmod{2^{64}}$$
$$\dots$$
$$H_7 = (H_7 + h) \pmod{2^{64}}$$

After the final block is processed, $H_0, H_1, H_2, H_3, H_4, H_5, H_6, H_7$ are each formatted as 16-character hexadecimal strings (with leading zero padding) and concatenated:
$$\text{Digest} = \text{hex}(H_0) \parallel \text{hex}(H_1) \parallel \dots \parallel \text{hex}(H_7)$$
The resulting string is exactly **128 hexadecimal characters** (512 bits).

---

## 15. Avalanche Effect
The **Avalanche Effect** (Strict Avalanche Criterion - SAC) requires that flipping a single input bit should result in each output bit flipping with 50% probability.

In our project:
* Input 1: `"The quick brown fox jumps over the lazy dog"`
* Input 2: `"The quick brown fox jumps over the lazy dog."` *(1 period added)*
* **Observed Output**:
  * Flipped Hex Characters: **121 / 128 (94.53%)**
  * Flipped Bits (Hamming Distance): **261 / 512 (50.98%)**

This near-perfect ~50% bit flip rate proves the high diffusion property of SHA-512.

---

## 16. System Architecture

```
+-------------------------------------------------------------------------+
|                              USER INTERFACE                             |
|  [ Generator ]   [ Verification ]   [ Avalanche ]   [ Test Vectors ]    |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                       UI CONTROLLER (script.js)                         |
|   - Event listeners and DOM updates                                     |
|   - Avalanche metrics & character visualizer                            |
|   - Live function tester & automated test runner                        |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  MANUAL CRYPTO ENGINE (sha512.js)                       |
|   - UTF-8 Encoding & Padding Module                                     |
|   - 64-bit Word Processing (BigInt modulo 2^64)                         |
|   - Constants Table (H0..H7, K0..K79)                                   |
|   - Bitwise Operations (ROTR, SHR, Ch, Maj, Sigma, sigma)               |
|   - 80 Compression Rounds & 512-bit Digest Assembler                    |
+-------------------------------------------------------------------------+
                                     | (Validation Check)
                                     v
+-------------------------------------------------------------------------+
|                 BROWSER WEB CRYPTO API (Test Oracle)                    |
|   - crypto.subtle.digest("SHA-512") for bit-exact verification          |
+-------------------------------------------------------------------------+
```

---

## 17. Project Features
1. **Interactive Hash Generator**: Live input, character/byte counters, one-click preset messages, and instant hash generation.
2. **Step-by-Step Educational Inspector**: Expandable breakdown detailing message lengths, padding bytes, 1024-bit blocks, and intermediate round words.
3. **Data Integrity Verifier**: Case-insensitive 128-hex validation checking authenticity and detecting data tampering.
4. **Avalanche Effect Analyzer**: Live character diff matrix, bit-level Hamming distance calculations, and preset tests.
5. **Interactive 64-bit Function Tester**: Live playground to test $Ch$, $Maj$, $\Sigma_0$, and $\sigma_0$ with arbitrary 64-bit inputs.
6. **Implementation Verification**: Real-time bit-exact comparison against the browser's native Web Crypto API.
7. **Automated Test Vectors Suite**: Tests standard NIST vectors with instant PASS/FAIL status badges.
8. **Modern Aesthetic UI**: Sleek dark mode glassmorphism interface, fully responsive and accessible.

---

## 18. Testing
Testing was carried out across multiple dimensions:
1. **Standard NIST Vectors**: Tested empty string `""`, `"abc"`, `"Hello World"`, and standard pangrams.
2. **Multi-block Inputs**: Tested long strings ($> 1000$ characters) spanning multiple 1024-bit blocks.
3. **Boundary Padding Conditions**: Tested messages of lengths 111, 112, 113, 127, 128 bytes to verify padding rollover across block boundaries.
4. **Automated Reference Comparison**: Every test vector was automatically verified against `crypto.subtle.digest("SHA-512")`.

---

## 19. Test Results

| Test Vector | Input Sample | Manual SHA-512 Digest (Prefix...Suffix) | Web Crypto Reference | Result |
| :--- | :--- | :--- | :--- | :---: |
| **Empty String** | `""` | `cf83e1357eefb8bd...f927da3e` | `cf83e1357eefb8bd...f927da3e` | **PASS ✓** |
| **Short "abc"** | `"abc"` | `ddaf35a193617aba...a54ca49f` | `ddaf35a193617aba...a54ca49f` | **PASS ✓** |
| **Word "Hello"** | `"Hello"` | `3615f80c9d293ed7...6b03f315` | `3615f80c9d293ed7...6b03f315` | **PASS ✓** |
| **"Hello World"**| `"Hello World"` | `2c74fd17edafd80e...b1447f459b` | `2c74fd17edafd80e...b1447f459b` | **PASS ✓** |
| **Pangram** | `"The quick brown..."` | `07e547d9586f6a73...854fee6` | `07e547d9586f6a73...854fee6` | **PASS ✓** |
| **1000 'a's** | `"aaa..." (1000 chars)` | `e7c445084c70d4f2...e632551` | `e7c445084c70d4f2...e632551` | **PASS ✓** |

**Final Verification Result**: **100% PASS** on all standard test vectors.

---

## 20. Advantages
* **High Security Margin**: 512-bit digest size provides $2^{256}$ security strength against collision and birthday attacks.
* **Optimized for 64-bit Architectures**: Native 64-bit arithmetic executes efficiently on modern CPU hardware.
* **Zero External Dependencies**: Clean, standalone code that runs in any modern browser without npm packages or backend servers.
* **Privacy Preserving**: 100% client-side computation; no user data leaves the browser.

---

## 21. Limitations
* **Length Extension Vulnerability**: Like all standard Merkle–Damgård hash functions, raw SHA-512 is vulnerable to length extension attacks if used naively as a MAC (fixed by using HMAC-SHA-512).
* **JavaScript BigInt Overhead**: While highly accurate, JavaScript `BigInt` operations are slower than native compiled C/Rust implementations.
* **Not Suitable for Password Storage Directly**: Because SHA-512 is fast, it should be combined with salt and key-stretching functions (such as PBKDF2, bcrypt, or Argon2) for password hashing.

---

## 22. Applications
* **Digital Signatures**: Used in RSA-PSS, ECDSA, and Ed25519 signature schemes.
* **TLS / HTTPS Certificates**: Secures cryptographic handshakes and digital identity verification.
* **Blockchain and Cryptocurrencies**: Used in block verification and transaction hashing.
* **Software Integrity Verification**: Distribution checksums (e.g. Linux ISOs, Git commits, package verification).
* **HMAC (Hash-based Message Authentication Codes)**: Keyed authentication in API security and OAuth tokens.

---

## 23. Conclusion
This project successfully designed, implemented, and verified the **SHA-512 Cryptographic Hash Function** from mathematical fundamentals according to NIST FIPS 180-4 and RFC 6234 standards. By implementing the complete pipeline using JavaScript `BigInt` 64-bit arithmetic, the project demonstrates how data padding, message expansion, non-linear boolean operations, and 80 compression rounds work together to produce secure, collision-resistant cryptographic digests.

---

## 24. Future Scope
* **HMAC-SHA-512 Support**: Implement Keyed-Hash Message Authentication Code (HMAC) on top of our manual SHA-512 engine.
* **File Hashing via Web Streams**: Add support for hashing multi-gigabyte files using incremental chunked streaming.
* **WebAssembly Acceleration**: Build a companion C/Rust WebAssembly implementation to compare performance benchmarks against JavaScript BigInt.
* **SHA-3 (Keccak) Comparison**: Add an interactive module comparing Merkle–Damgård (SHA-2) architecture with Sponge Construction (SHA-3).

---

## Project Structure

```
SHA512-Project/
├── index.html        # Main web interface (UI & all 8 sections)
├── style.css         # Modern dark mode and responsive layout styles
├── script.js         # Interactive controller, event handlers & test suite
├── sha512.js         # 100% manual SHA-512 cryptographic engine (BigInt)
└── README.md         # Comprehensive project documentation
```

### How to Run:
Simply double-click `index.html` or open it in any modern web browser (Chrome, Firefox, Edge, Safari). No installation, build steps, or server required!
