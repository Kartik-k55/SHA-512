/**
 * ==============================================================================
 * CRYPTOGRAPHY MINI PROJECT: IMPLEMENTATION OF SHA-512 HASH FUNCTION
 * ==============================================================================
 * File: sha512.js
 * Description: Pure Vanilla JavaScript implementation of NIST FIPS PUB 180-4
 *              and RFC 6234 Secure Hash Algorithm 512 (SHA-512).
 *
 * NOTE: This is a standalone, educational, 100% manual implementation using
 * JavaScript BigInt for native 64-bit arithmetic modulo 2^64.
 *
 * It does NOT rely on crypto.subtle or any external hashing library.
 * ==============================================================================
 */

(function (global) {
    'use strict';

    // 64-bit bitmask (2^64 - 1) to ensure all operations remain within 64 bits (unsigned modulo 2^64)
    const MASK_64 = 0xFFFFFFFFFFFFFFFFn;

    /**
     * ==========================================================================
     * 1. INITIAL HASH VALUES (H0 - H7)
     * ==========================================================================
     * These eight 64-bit constant words represent the first 64 bits of the
     * fractional parts of the square roots of the first 8 prime numbers (2 to 19).
     * (NIST FIPS 180-4 Section 5.3.5)
     */
    const INITIAL_HASH = [
        0x6a09e667f3bcc908n, // sqrt(2)  fractional part
        0xbb67ae8584caa73bn, // sqrt(3)  fractional part
        0x3c6ef372fe94f82bn, // sqrt(5)  fractional part
        0xa54ff53a5f1d36f1n, // sqrt(7)  fractional part
        0x510e527fade682d1n, // sqrt(11) fractional part
        0x9b05688c2b3e6c1fn, // sqrt(13) fractional part
        0x1f83d9abfb41bd6bn, // sqrt(17) fractional part
        0x5be0cd19137e2179n  // sqrt(19) fractional part
    ];

    /**
     * ==========================================================================
     * 2. SHA-512 ROUND CONSTANTS (K0 - K79)
     * ==========================================================================
     * Eighty constant 64-bit words representing the first 64 bits of the
     * fractional parts of the cube roots of the first 80 prime numbers (2 to 409).
     * (NIST FIPS 180-4 Section 4.2.3 / RFC 6234 Section 5.2)
     */
    const K = [
        0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
        0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
        0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
        0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
        0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
        0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
        0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
        0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
        0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
        0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
        0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
        0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
        0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
        0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
        0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
        0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
        0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
        0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
        0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
        0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
    ];

    /**
     * ==========================================================================
     * 3. BITWISE PRIMITIVE OPERATIONS (ROTR & SHR)
     * ==========================================================================
     */

    /**
     * 64-bit Circular Right Rotation (ROTR^n(x))
     * Rotates 64-bit BigInt x right by n positions.
     * @param {bigint} x - 64-bit integer
     * @param {number|bigint} n - Number of bits to rotate (0 <= n < 64)
     * @returns {bigint} - Rotated 64-bit integer
     */
    function ROTR(x, n) {
        const shift = BigInt(n);
        return ((x >> shift) | (x << (64n - shift))) & MASK_64;
    }

    /**
     * 64-bit Right Logical Shift (SHR^n(x))
     * Shifts 64-bit BigInt x right by n positions, padding with zeros on left.
     * @param {bigint} x - 64-bit integer
     * @param {number|bigint} n - Number of bits to shift
     * @returns {bigint} - Shifted 64-bit integer
     */
    function SHR(x, n) {
        return (x >> BigInt(n)) & MASK_64;
    }

    /**
     * ==========================================================================
     * 4. NON-LINEAR LOGICAL FUNCTIONS
     * ==========================================================================
     */

    /**
     * Choose Function: Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
     * For each bit, if x is 1, chooses the corresponding bit in y;
     * otherwise chooses the bit in z.
     */
    function Ch(x, y, z) {
        return (x & y) ^ ((~x) & z);
    }

    /**
     * Majority Function: Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
     * For each bit, returns 1 if at least two of (x, y, z) have a 1 at that position.
     */
    function Maj(x, y, z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    /**
     * ==========================================================================
     * 5. SIGMA TRANSFORMATION FUNCTIONS
     * ==========================================================================
     */

    /**
     * Big Sigma 0: Σ0(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)
     * Used in compression round calculation of T2.
     */
    function Sigma0(x) {
        return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
    }

    /**
     * Big Sigma 1: Σ1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)
     * Used in compression round calculation of T1.
     */
    function Sigma1(x) {
        return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
    }

    /**
     * Small Sigma 0: σ0(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)
     * Used in extending message schedule W[t].
     */
    function sigma0(x) {
        return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
    }

    /**
     * Small Sigma 1: σ1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)
     * Used in extending message schedule W[t].
     */
    function sigma1(x) {
        return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);
    }

    /**
     * ==========================================================================
     * 6. UTF-8 ENCODING HELPER
     * ==========================================================================
     * Converts a JavaScript string to a Uint8Array of UTF-8 encoded bytes.
     * @param {string} str - Input text
     * @returns {Uint8Array} - Array of byte values (0-255)
     */
    function encodeUtf8(str) {
        if (typeof TextEncoder !== 'undefined') {
            return new TextEncoder().encode(str);
        }
        // Fallback UTF-8 manual encoding
        const utf8 = [];
        for (let i = 0; i < str.length; i++) {
            let charcode = str.charCodeAt(i);
            if (charcode < 0x80) utf8.push(charcode);
            else if (charcode < 0x800) {
                utf8.push(0xc0 | (charcode >> 6),
                          0x80 | (charcode & 0x3f));
            }
            else if (charcode < 0xd800 || charcode >= 0xe000) {
                utf8.push(0xe0 | (charcode >> 12),
                          0x80 | ((charcode >> 6) & 0x3f),
                          0x80 | (charcode & 0x3f));
            }
            else {
                // Surrogate pair
                i++;
                charcode = 0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
                utf8.push(0xf0 | (charcode >> 18),
                          0x80 | ((charcode >> 12) & 0x3f),
                          0x80 | ((charcode >> 6) & 0x3f),
                          0x80 | (charcode & 0x3f));
            }
        }
        return new Uint8Array(utf8);
    }

    /**
     * ==========================================================================
     * 7. MESSAGE PADDING AND 1024-BIT BLOCK FORMATION
     * ==========================================================================
     * Given input bytes of length L:
     * 1. Append single bit '1' (0x80 byte)
     * 2. Append k zero bytes such that (L + 1 + k) = 112 mod 128 (896 mod 1024 bits)
     * 3. Append original message length L in bits as a 128-bit big-endian integer (16 bytes)
     *
     * Total resulting length will be a strict multiple of 128 bytes (1024 bits).
     * @param {Uint8Array} rawBytes
     * @returns {{ paddedBytes: Uint8Array, blockCount: number, bitLength: bigint }}
     */
    function padMessage(rawBytes) {
        const msgLen = rawBytes.length; // in bytes
        const bitLen = BigInt(msgLen) * 8n; // in bits

        // Calculate padding zeros needed
        // Formula: (msgLen + 1 + padZeros + 16) % 128 === 0
        let padZeros = (128 - ((msgLen + 1 + 16) % 128)) % 128;
        const totalLen = msgLen + 1 + padZeros + 16;

        const padded = new Uint8Array(totalLen);
        padded.set(rawBytes, 0);

        // Append 0x80 (bit 1 followed by seven 0s)
        padded[msgLen] = 0x80;
        // Remaining bytes up to totalLen - 16 are 0x00 by default in typed array

        // Append 128-bit message length (in bits) as big-endian
        const view = new DataView(padded.buffer);
        const highLen = (bitLen >> 64n) & MASK_64; // bits 64..127
        const lowLen = bitLen & MASK_64;          // bits 0..63

        view.setBigUint64(totalLen - 16, highLen, false); // false = big-endian
        view.setBigUint64(totalLen - 8, lowLen, false);

        return {
            paddedBytes: padded,
            blockCount: totalLen / 128,
            bitLength: bitLen
        };
    }

    /**
     * ==========================================================================
     * 8. MAIN SHA-512 FUNCTION
     * ==========================================================================
     * Computes the 512-bit message digest of an arbitrary text message.
     *
     * @param {string} message - Input string to hash
     * @returns {string} - Exactly 128 hexadecimal characters (lowercase)
     */
    function sha512(message) {
        // Step 1: UTF-8 encode input string
        const rawBytes = encodeUtf8(message);

        // Step 2 & 3: Pad message and append 128-bit length
        const { paddedBytes, blockCount } = padMessage(rawBytes);

        // Step 4: Initialize 8 working hash variables with standard H0..H7 constants
        let h0 = INITIAL_HASH[0];
        let h1 = INITIAL_HASH[1];
        let h2 = INITIAL_HASH[2];
        let h3 = INITIAL_HASH[3];
        let h4 = INITIAL_HASH[4];
        let h5 = INITIAL_HASH[5];
        let h6 = INITIAL_HASH[6];
        let h7 = INITIAL_HASH[7];

        const view = new DataView(paddedBytes.buffer);
        const W = new Array(80); // Message schedule array (80 64-bit words)

        // Step 5: Process each 1024-bit (128-byte) message block
        for (let blockIdx = 0; blockIdx < blockCount; blockIdx++) {
            const blockOffset = blockIdx * 128;

            // Step 5a: Prepare message schedule W[0..15] from current block (16 words)
            for (let t = 0; t < 16; t++) {
                W[t] = view.getBigUint64(blockOffset + t * 8, false);
            }

            // Step 5b: Extend message schedule W[16..79]
            for (let t = 16; t < 80; t++) {
                const s1 = sigma1(W[t - 2]);
                const s0 = sigma0(W[t - 15]);
                W[t] = (s1 + W[t - 7] + s0 + W[t - 16]) & MASK_64;
            }

            // Step 5c: Initialize working variables with current intermediate hash values
            let a = h0;
            let b = h1;
            let c = h2;
            let d = h3;
            let e = h4;
            let f = h5;
            let g = h6;
            let h = h7;

            // Step 5d: Execute 80 compression rounds
            for (let t = 0; t < 80; t++) {
                const T1 = (h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t]) & MASK_64;
                const T2 = (Sigma0(a) + Maj(a, b, c)) & MASK_64;

                h = g;
                g = f;
                f = e;
                e = (d + T1) & MASK_64;
                d = c;
                c = b;
                b = a;
                a = (T1 + T2) & MASK_64;
            }

            // Step 5e: Compute the intermediate hash values for this block (addition modulo 2^64)
            h0 = (h0 + a) & MASK_64;
            h1 = (h1 + b) & MASK_64;
            h2 = (h2 + c) & MASK_64;
            h3 = (h3 + d) & MASK_64;
            h4 = (h4 + e) & MASK_64;
            h5 = (h5 + f) & MASK_64;
            h6 = (h6 + g) & MASK_64;
            h7 = (h7 + h) & MASK_64;
        }

        // Step 6: Produce final 512-bit digest by concatenating H0..H7 formatted as 16-hex digit words
        const digestHex = [h0, h1, h2, h3, h4, h5, h6, h7]
            .map(val => val.toString(16).padStart(16, '0'))
            .join('');

        return digestHex;
    }

    /**
     * ==========================================================================
     * 9. EDUCATIONAL STEP-BY-STEP DETAILED HASH FUNCTION
     * ==========================================================================
     * Returns structured step details for interactive visualization in the UI.
     */
    function sha512Detailed(message) {
        const rawBytes = encodeUtf8(message);
        const { paddedBytes, blockCount, bitLength } = padMessage(rawBytes);

        let h0 = INITIAL_HASH[0];
        let h1 = INITIAL_HASH[1];
        let h2 = INITIAL_HASH[2];
        let h3 = INITIAL_HASH[3];
        let h4 = INITIAL_HASH[4];
        let h5 = INITIAL_HASH[5];
        let h6 = INITIAL_HASH[6];
        let h7 = INITIAL_HASH[7];

        const view = new DataView(paddedBytes.buffer);
        const blocksInfo = [];

        for (let blockIdx = 0; blockIdx < blockCount; blockIdx++) {
            const blockOffset = blockIdx * 128;
            const W = new Array(80);

            for (let t = 0; t < 16; t++) {
                W[t] = view.getBigUint64(blockOffset + t * 8, false);
            }

            for (let t = 16; t < 80; t++) {
                const s1 = sigma1(W[t - 2]);
                const s0 = sigma0(W[t - 15]);
                W[t] = (s1 + W[t - 7] + s0 + W[t - 16]) & MASK_64;
            }

            let a = h0, b_var = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            const roundSamples = []; // Sample specific rounds for educational inspection (0, 1, 39, 79)

            for (let t = 0; t < 80; t++) {
                const T1 = (h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t]) & MASK_64;
                const T2 = (Sigma0(a) + Maj(a, b_var, c)) & MASK_64;

                if (t === 0 || t === 1 || t === 79) {
                    roundSamples.push({
                        round: t,
                        a: a.toString(16).padStart(16, '0'),
                        e: e.toString(16).padStart(16, '0'),
                        T1: T1.toString(16).padStart(16, '0'),
                        T2: T2.toString(16).padStart(16, '0'),
                        W_t: W[t].toString(16).padStart(16, '0'),
                        K_t: K[t].toString(16).padStart(16, '0')
                    });
                }

                h = g;
                g = f;
                f = e;
                e = (d + T1) & MASK_64;
                d = c;
                c = b_var;
                b_var = a;
                a = (T1 + T2) & MASK_64;
            }

            h0 = (h0 + a) & MASK_64;
            h1 = (h1 + b_var) & MASK_64;
            h2 = (h2 + c) & MASK_64;
            h3 = (h3 + d) & MASK_64;
            h4 = (h4 + e) & MASK_64;
            h5 = (h5 + f) & MASK_64;
            h6 = (h6 + g) & MASK_64;
            h7 = (h7 + h) & MASK_64;

            blocksInfo.push({
                blockIndex: blockIdx,
                initialWords: W.slice(0, 16).map(w => w.toString(16).padStart(16, '0')),
                extendedSample: W.slice(16, 20).map(w => w.toString(16).padStart(16, '0')),
                roundSamples: roundSamples,
                intermediateH: [h0, h1, h2, h3, h4, h5, h6, h7].map(val => val.toString(16).padStart(16, '0'))
            });
        }

        const digest = [h0, h1, h2, h3, h4, h5, h6, h7]
            .map(val => val.toString(16).padStart(16, '0'))
            .join('');

        return {
            inputMessage: message,
            byteLength: rawBytes.length,
            bitLength: bitLength.toString(),
            totalPaddedBytes: paddedBytes.length,
            totalPaddedBits: paddedBytes.length * 8,
            blockCount: blockCount,
            blocks: blocksInfo,
            finalDigest: digest,
            initialH: INITIAL_HASH.map(val => val.toString(16).padStart(16, '0'))
        };
    }

    /**
     * ==========================================================================
     * 10. EXPORT / GLOBAL REGISTRATION
     * ==========================================================================
     */
    const SHA512Module = {
        hash: sha512,
        hashDetailed: sha512Detailed,
        ROTR: ROTR,
        SHR: SHR,
        Ch: Ch,
        Maj: Maj,
        Sigma0: Sigma0,
        Sigma1: Sigma1,
        sigma0: sigma0,
        sigma1: sigma1,
        INITIAL_HASH: INITIAL_HASH,
        K: K
    };

    // Attach to global window or exports
    if (typeof exports !== 'undefined') {
        if (typeof module !== 'undefined' && module.exports) {
            exports = module.exports = SHA512Module;
        }
        exports.sha512 = sha512;
        exports.SHA512 = SHA512Module;
    } else {
        global.sha512 = sha512;
        global.SHA512 = SHA512Module;
    }

})(typeof window !== 'undefined' ? window : globalThis);
