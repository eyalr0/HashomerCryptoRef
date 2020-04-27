from HashomerCryptoRef.source.bytes_utils import hex_to_bytes, pad
from HashomerCryptoRef.source.crypto import encrypt, hmac_sha256

KEY_SIZE = 16


def test_aes():
    """
    Test Adapted from Section:
      C.1 https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
    (positive test)
    """

    plain = hex_to_bytes('00112233445566778899aabbccddeeff')
    key = hex_to_bytes('000102030405060708090a0b0c0d0e0f')
    expected_cipher = hex_to_bytes('69c4e0d86a7b0430d8cdb78070b4c55a')

    result = encrypt(key, plain)
    assert result == expected_cipher, "AES test failed"


def test_hmac():
    """
    Test Adapted from :
        4.3 https://tools.ietf.org/html/rfc4231#section-4
    (positive test)
    """
    key = hex_to_bytes("4a656665")
    message = hex_to_bytes("7768617420646f2079612077616e7420666f72206e6f7468696e673f")
    expected_signature = hex_to_bytes('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')

    key = pad(key, KEY_SIZE)
    assert hmac_sha256(key, message) == expected_signature, "HMAC test failed"
