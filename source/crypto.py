from hashlib import sha256
import hmac

use_cryptography = True
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    use_cryptography = False
    from Crypto.Cipher import AES


AES_BLOCK_SIZE = 16
KEY_LEN = 16


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC with SHA256 hash function.
    :param key:     array of size 16 bytes.
    :param data:    data to sign.
    :return:
    """

    assert len(key) == KEY_LEN, "We only support 128 bit key, but len(key) = {})".format(len(key))
    return hmac.new(key, data, sha256).digest()


def encrypt_cryptography(key: bytes, plain: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    return encryptor.update(plain)


def encrypt_cryptodome(key: bytes, plain: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plain)


def encrypt(key: bytes, plain: bytes) -> bytes:
    """
    Encrypt a block with AES encryption.
    :param key:     array of size 16 bytes.
    :param plain:   array of size 16 bytes.
    :return:        the encrypted array is size 16 bytes.
    """

    assert len(key) == KEY_LEN, "We only support 128 bit key, but len(key) = {})".format(len(key))
    assert len(plain) == KEY_LEN, "We only support 128 bit key, but len(key) = {})".format(len(key))

    if use_cryptography:
        return encrypt_cryptography(key, plain)

    return encrypt_cryptodome(key, plain)
