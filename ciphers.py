"""
CSI2108 Portfolio Part 1
PRNG + Stream Cipher (Geffe-style nonlinear LFSR combiner)
Block cipher (custom 9-byte SPN, 4 rounds, CTR mode)
"""

# ---------------------------------------------------------------
# 1. LFSR building block
# ---------------------------------------------------------------
class LFSR:
    def __init__(self, seed, taps, length):
        self.length = length
        self.mask = (1 << length) - 1
        self.state = seed & self.mask
        self.taps = taps  # bit positions (1-indexed from LSB) that feed the XOR

    def clock(self):
        # output bit is current LSB
        out = self.state & 1
        fb = 0
        for t in self.taps:
            fb ^= (self.state >> (t - 1)) & 1
        self.state = (self.state >> 1) | (fb << (self.length - 1))
        return out

# Primitive trinomials (period = 2^L - 1, full period, verified small examples)
LFSR_A = lambda seed: LFSR(seed, taps=(7, 3), length=7)    # x^7+x^3+1, period 127
LFSR_B = lambda seed: LFSR(seed, taps=(9, 4), length=9)    # x^9+x^4+1, period 511
LFSR_C = lambda seed: LFSR(seed, taps=(11, 2), length=11)  # x^11+x^2+1, period 2047

# ---------------------------------------------------------------
# 2. Geffe nonlinear combiner PRNG
# ---------------------------------------------------------------
class GeffePRNG:
    def __init__(self, seedA, seedB, seedC):
        self.a = LFSR_A(seedA)  # selector
        self.b = LFSR_B(seedB)
        self.c = LFSR_C(seedC)

    def next_bit(self):
        a = self.a.clock()
        b = self.b.clock()
        c = self.c.clock()
        return (a & b) ^ ((1 - a) & c)

    def next_byte(self):
        byte = 0
        for _ in range(8):
            byte = (byte << 1) | self.next_bit()
        return byte

# ---------------------------------------------------------------
# 3. Stream cipher
# ---------------------------------------------------------------
def stream_cipher_encrypt(plaintext: str, seedA, seedB, seedC):
    prng = GeffePRNG(seedA, seedB, seedC)
    pt_bytes = plaintext.encode('ascii')
    keystream = [prng.next_byte() for _ in pt_bytes]
    ct_bytes = bytes([p ^ k for p, k in zip(pt_bytes, keystream)])
    return ct_bytes, keystream

def stream_cipher_decrypt(ciphertext: bytes, seedA, seedB, seedC):
    prng = GeffePRNG(seedA, seedB, seedC)
    keystream = [prng.next_byte() for _ in ciphertext]
    pt_bytes = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
    return pt_bytes.decode('ascii'), keystream

TEST_MESSAGE = "CHIP-ID:16847; TYPE:Adult; BALANCE:$38.09; AUTH_KEY:56A81B7"

if __name__ == "__main__":
    print("Message length:", len(TEST_MESSAGE), "chars")
    seedA, seedB, seedC = 0b1011001, 0b101100110, 0b10110011010

    ct, ks = stream_cipher_encrypt(TEST_MESSAGE, seedA, seedB, seedC)
    print("Full ciphertext (hex):", ct.hex())

    # Worked example - first 4 characters
    print("\n--- Worked example: first 4 characters ---")
    for i in range(4):
        ch = TEST_MESSAGE[i]
        p = ord(ch)
        k = ks[i]
        c = p ^ k
        print(f"char={ch!r} p={p:3d} ({p:08b})  keystream={k:3d} ({k:08b})  cipher={c:3d} ({c:08b}) hex={c:02x}")

    pt2, ks2 = stream_cipher_decrypt(ct, seedA, seedB, seedC)
    print("\nDecryption matches original:", pt2 == TEST_MESSAGE)

# =================================================================
# BLOCK CIPHER (custom 9-byte / 72-bit SPN)
# =================================================================
import random

BLOCK_BYTES = 9  # 72 bits

def build_sbox(seed=2026):
    rnd = random.Random(seed)
    box = list(range(256))
    rnd.shuffle(box)
    inv = [0]*256
    for i, v in enumerate(box):
        inv[v] = i
    return box, inv

SBOX, INV_SBOX = build_sbox()

def build_bit_permutation(seed=7):
    rnd = random.Random(seed)
    perm = list(range(72))
    rnd.shuffle(perm)
    inv = [0]*72
    for i, v in enumerate(perm):
        inv[v] = i
    return perm, inv

BIT_PERM, INV_BIT_PERM = build_bit_permutation()

def bytes_to_bits(b):
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for bit in bits[i:i+8]:
            val = (val << 1) | bit
        out.append(val)
    return bytes(out)

def permute_bits(block9, perm):
    bits = bytes_to_bits(block9)
    new_bits = [0]*72
    for i, p in enumerate(perm):
        new_bits[i] = bits[p]
    return bits_to_bytes(new_bits)

def substitute(block9, sbox):
    return bytes(sbox[b] for b in block9)

def key_schedule(master_key9, num_rounds):
    # rotate the 72-bit key left by (i*11+3) bits each round, XOR round constant into byte0
    bits = bytes_to_bits(master_key9)
    round_keys = []
    for r in range(num_rounds):
        shift = (r * 11 + 3) % 72
        rk_bits = bits[shift:] + bits[:shift]
        rk = bytearray(bits_to_bytes(rk_bits))
        rk[0] ^= (r + 1)  # round constant
        round_keys.append(bytes(rk))
    return round_keys

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def block_encrypt(block9: bytes, master_key9: bytes, rounds=4):
    round_keys = key_schedule(master_key9, rounds)
    state = block9
    for r in range(rounds):
        state = xor_bytes(state, round_keys[r])      # key mixing
        state = substitute(state, SBOX)               # confusion
        state = permute_bits(state, BIT_PERM)          # diffusion
    return state

def block_decrypt(block9: bytes, master_key9: bytes, rounds=4):
    round_keys = key_schedule(master_key9, rounds)
    state = block9
    for r in reversed(range(rounds)):
        state = permute_bits(state, INV_BIT_PERM)
        state = substitute(state, INV_SBOX)
        state = xor_bytes(state, round_keys[r])
    return state

def pkcs_pad(data: bytes, block_size=BLOCK_BYTES):
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs_unpad(data: bytes):
    pad_len = data[-1]
    return data[:-pad_len]

def ctr_encrypt(plaintext: bytes, master_key9: bytes, nonce7: bytes, rounds=4):
    assert len(nonce7) == 7  # 7-byte nonce + 2-byte counter = 9 bytes
    out = bytearray()
    counter = 0
    for i in range(0, len(plaintext), BLOCK_BYTES):
        chunk = plaintext[i:i+BLOCK_BYTES]
        ctr_block = nonce7 + counter.to_bytes(2, 'big')
        ks_block = block_encrypt(ctr_block, master_key9, rounds)
        out.extend(x ^ y for x, y in zip(chunk, ks_block[:len(chunk)]))
        counter += 1
    return bytes(out)

if __name__ == "__main__":
    print("\n\n=== BLOCK CIPHER ===")
    master_key = b"AB-TR2026"  # 9 bytes
    assert len(master_key) == 9
    pt_padded = pkcs_pad(TEST_MESSAGE.encode('ascii'))
    print("Padded length:", len(pt_padded), "bytes ->", len(pt_padded)//9, "blocks")

    # Direct ECB-style block encryption (2.1 demonstration)
    ct_blocks = b"".join(block_encrypt(pt_padded[i:i+9], master_key, rounds=4)
                          for i in range(0, len(pt_padded), 9))
    print("Direct block ciphertext (hex):", ct_blocks.hex())

    dec_blocks = b"".join(block_decrypt(ct_blocks[i:i+9], master_key, rounds=4)
                           for i in range(0, len(ct_blocks), 9))
    print("Decrypt+unpad matches original:", pkcs_unpad(dec_blocks) == TEST_MESSAGE.encode('ascii'))

    # CTR mode (2.2 chosen mode)
    nonce = bytes([16, 8, 47, 0, 0, 0, 1])  # example: card-id-derived nonce, 7 bytes
    ct_ctr = ctr_encrypt(TEST_MESSAGE.encode('ascii'), master_key, nonce, rounds=4)
    print("\nCTR ciphertext (hex, no padding needed):", ct_ctr.hex())
    # decrypt by re-generating same keystream (CTR is symmetric)
    pt_back = ctr_encrypt(ct_ctr, master_key, nonce, rounds=4)
    print("CTR round-trip matches original:", pt_back == TEST_MESSAGE.encode('ascii'))

if __name__ == "__main__":
    print("\n\n=== STATISTICAL CHECKS ===")
    # --- Confusion test: flip 1 bit of key, fixed nonce, compare ciphertexts ---
    key1 = bytearray(b"AB-TR2026")
    key2 = bytearray(key1)
    key2[0] ^= 0x01   # flip lowest bit of first key byte
    nonce = bytes([16, 8, 47, 0, 0, 0, 1])

    ct1 = ctr_encrypt(TEST_MESSAGE.encode('ascii'), bytes(key1), nonce, rounds=4)
    ct2 = ctr_encrypt(TEST_MESSAGE.encode('ascii'), bytes(key2), nonce, rounds=4)

    def hamming_distance_bits(b1, b2):
        return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))

    total_bits = len(ct1) * 8
    diff_bits = hamming_distance_bits(ct1, ct2)
    print(f"Key bit flip -> {diff_bits}/{total_bits} ciphertext bits changed "
          f"({100*diff_bits/total_bits:.1f}%)")

    # --- Round-adjustment test ---
    print("\nRounds | bits changed | % changed")
    round_results = []
    for r in range(1, 7):
        c1 = ctr_encrypt(TEST_MESSAGE.encode('ascii'), bytes(key1), nonce, rounds=r)
        c2 = ctr_encrypt(TEST_MESSAGE.encode('ascii'), bytes(key2), nonce, rounds=r)
        d = hamming_distance_bits(c1, c2)
        pct = 100*d/total_bits
        round_results.append((r, d, pct))
        print(f"{r:6d} | {d:12d} | {pct:6.1f}%")
