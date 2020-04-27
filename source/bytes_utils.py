STRINGS = {x: y.encode('ascii') for x, y in {
    'id': "IdentityKey",
    'id_com': "IdentityCommitment",
    'master0': "DeriveMasterFirstKey",
    'master': "DeriveMasterKey",
    'ddaykey': "DeriveDayKey",
    'dverif': "DeriveVerificationKey",
    'depoch': "DeriveEpoch",
    'verifkey': "VerificationKey"
}.items()}


def num_to_bytes(num: int, num_bytes: int) -> bytes:
    res = []
    for i in range(num_bytes):
        res.append(num & 0xff)
        num >>= 8
    assert num == 0, "Sanity check"
    return bytes(res)


def hex_to_bytes(s: str) -> bytes:
    return bytes([int(s[i:i + 2], 16) for i in range(0, len(s), 2)])


def pad(array: bytes, size: int) -> bytes:
    assert len(array) <= size, "Padded array should not be smaller."
    return array + bytes([0] * (size - len(array)))


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes([x ^ y for x, y in zip(a, b)])
