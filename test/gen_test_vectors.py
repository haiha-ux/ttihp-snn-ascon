#!/usr/bin/env python3
"""Generate Ascon-128 test vectors for RTL verification."""

def rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def ascon_round(x, rc):
    x[2] ^= rc
    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1]
    t = [(x[i] ^ 0xFFFFFFFFFFFFFFFF) & x[(i+1)%5] for i in range(5)]
    for i in range(5):
        x[i] ^= t[(i+1)%5]
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] ^= 0xFFFFFFFFFFFFFFFF
    rotations = [(19,28),(61,39),(1,6),(10,17),(7,41)]
    for i,(r1,r2) in enumerate(rotations):
        x[i] ^= rotr64(x[i], r1) ^ rotr64(x[i], r2)

def ascon_permutation(x, rounds):
    rc = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
    for i in range(12 - rounds, 12):
        ascon_round(x, rc[i])

def ascon128_encrypt(key, nonce, plaintext_blocks):
    IV = 0x80400c0600000000
    K0 = (key >> 64) & 0xFFFFFFFFFFFFFFFF
    K1 = key & 0xFFFFFFFFFFFFFFFF
    N0 = (nonce >> 64) & 0xFFFFFFFFFFFFFFFF
    N1 = nonce & 0xFFFFFFFFFFFFFFFF

    x = [IV, K0, K1, N0, N1]
    ascon_permutation(x, 12)
    x[3] ^= K0
    x[4] ^= K1
    x[4] ^= 1  # domain separator (no AD)

    ciphertext = []
    for i, pt in enumerate(plaintext_blocks):
        ct = x[0] ^ pt
        ciphertext.append(ct)
        if i < len(plaintext_blocks) - 1:
            x[0] = ct
            ascon_permutation(x, 6)
        else:
            x[0] = ct

    x[1] ^= K0
    x[2] ^= K1
    ascon_permutation(x, 12)
    tag = ((x[3] ^ K0) << 64) | (x[4] ^ K1)

    return ciphertext, tag

def ascon128_decrypt(key, nonce, ciphertext_blocks, tag):
    IV = 0x80400c0600000000
    K0 = (key >> 64) & 0xFFFFFFFFFFFFFFFF
    K1 = key & 0xFFFFFFFFFFFFFFFF
    N0 = (nonce >> 64) & 0xFFFFFFFFFFFFFFFF
    N1 = nonce & 0xFFFFFFFFFFFFFFFF

    x = [IV, K0, K1, N0, N1]
    ascon_permutation(x, 12)
    x[3] ^= K0
    x[4] ^= K1
    x[4] ^= 1

    plaintext = []
    for i, ct in enumerate(ciphertext_blocks):
        pt = x[0] ^ ct
        plaintext.append(pt)
        x[0] = ct
        if i < len(ciphertext_blocks) - 1:
            ascon_permutation(x, 6)

    x[1] ^= K0
    x[2] ^= K1
    ascon_permutation(x, 12)
    computed_tag = ((x[3] ^ K0) << 64) | (x[4] ^ K1)

    return plaintext, computed_tag == tag

def to_bytes(val, n):
    return [(val >> (8*(n-1-i))) & 0xFF for i in range(n)]

def bytes_hex(bs):
    return ' '.join(f'{b:02x}' for b in bs)

def gen_vh_array(name, byte_list):
    """Generate Verilog hex array initialization."""
    lines = []
    for i, b in enumerate(byte_list):
        lines.append(f"    {name}[{i}] = 8'h{b:02x};")
    return '\n'.join(lines)

# ============================================================
# Test Vectors
# ============================================================
vectors = [
    # (name, key_hex, nonce_hex, plaintext_blocks)
    ("TV0_zeros",
     0x00000000000000000000000000000000,
     0x00000000000000000000000000000000,
     [0x0000000000000000]),

    ("TV1_ones",
     0x01010101010101010101010101010101,
     0x02020202020202020202020202020202,
     [0xAAAAAAAAAAAAAAAA, 0xBBBBBBBBBBBBBBBB]),

    ("TV2_counting",
     0x000102030405060708090A0B0C0D0E0F,
     0x00112233445566778899AABBCCDDEEFF,
     [0x0011223344556677]),

    ("TV3_3blocks",
     0xDEADBEEFCAFEBABE0123456789ABCDEF,
     0xFEDCBA9876543210ABCDEF0123456789,
     [0x1111111111111111, 0x2222222222222222, 0x3333333333333333]),

    ("TV4_ff",
     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
     [0xFFFFFFFFFFFFFFFF]),
]

print("// Auto-generated Ascon-128 test vectors")
print(f"// {len(vectors)} test vectors\n")

for vi, (name, key, nonce, pt_blocks) in enumerate(vectors):
    ct_blocks, tag = ascon128_encrypt(key, nonce, pt_blocks)

    # Also verify decrypt
    dec_blocks, tag_ok = ascon128_decrypt(key, nonce, ct_blocks, tag)
    assert tag_ok, f"Decrypt tag mismatch for {name}!"
    for j, (p, d) in enumerate(zip(pt_blocks, dec_blocks)):
        assert p == d, f"Decrypt plaintext mismatch block {j} for {name}!"

    print(f"// === {name} ===")
    print(f"// Key:   {key:032x}")
    print(f"// Nonce: {nonce:032x}")
    print(f"// PT blocks: {len(pt_blocks)}")
    for j, pt in enumerate(pt_blocks):
        print(f"//   PT[{j}]: {bytes_hex(to_bytes(pt, 8))}")
    for j, ct in enumerate(ct_blocks):
        print(f"//   CT[{j}]: {bytes_hex(to_bytes(ct, 8))}")
    print(f"//   Tag:  {bytes_hex(to_bytes(tag, 16))}")

    # Flatten to bytes for RTL comparison
    key_bytes = to_bytes(key >> 64, 8) + to_bytes(key & 0xFFFFFFFFFFFFFFFF, 8)
    nonce_bytes = to_bytes(nonce >> 64, 8) + to_bytes(nonce & 0xFFFFFFFFFFFFFFFF, 8)
    pt_bytes = []
    for pt in pt_blocks:
        pt_bytes.extend(to_bytes(pt, 8))
    ct_bytes = []
    for ct in ct_blocks:
        ct_bytes.extend(to_bytes(ct, 8))
    tag_bytes = to_bytes(tag, 16)
    expected = ct_bytes + tag_bytes

    print(f"// Expected output ({len(expected)} bytes): {bytes_hex(expected)}")
    print()

# Print summary
print("// Summary of expected outputs for RTL comparison:")
for vi, (name, key, nonce, pt_blocks) in enumerate(vectors):
    ct_blocks, tag = ascon128_encrypt(key, nonce, pt_blocks)
    ct_bytes = []
    for ct in ct_blocks:
        ct_bytes.extend(to_bytes(ct, 8))
    tag_bytes = to_bytes(tag, 16)
    n_ct = len(pt_blocks) * 8
    n_total = n_ct + 16
    print(f"// TV{vi} ({name}): {n_total} bytes = {n_ct} CT + 16 tag")
    print(f"//   {bytes_hex(ct_bytes + tag_bytes)}")
