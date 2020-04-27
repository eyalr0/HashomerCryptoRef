from typing import Tuple
from .crypto import encrypt, hmac_sha256 as hmac
from .bytes_utils import num_to_bytes, STRINGS


KEY_LEN = 16


def get_key_master_com(key_id: bytes, user_id: bytes) -> bytes:
    return hmac(key_id, user_id + STRINGS['id_com'])[:KEY_LEN]


def get_key_epoch(pre_key: bytes, commit: bytes, day: bytes, epoch: bytes) -> bytes:
    return hmac(pre_key, commit + day + epoch + STRINGS['depoch'])[:KEY_LEN]


def get_key_commit_i(key_master_com: bytes, day: bytes) -> bytes:
    assert len(day) == 4
    return encrypt(key_master_com, day + b'\x00' * 12)


def get_epoch_keys(epoch_key: bytes, day: int, epoch: int) -> Tuple[bytes, bytes]:
    prefix = num_to_bytes(day, 4) + num_to_bytes(epoch, 1)
    epoch_enc = encrypt(epoch_key, prefix + b'\x00'*11)
    epoch_mac = encrypt(epoch_key, prefix + b'\x01' + b'\x00'*10)
    return epoch_enc, epoch_mac


def get_key_i_verification(key_master_verification: bytes, day: int) -> bytes:
    return hmac(key_master_verification, num_to_bytes(day, 4) + STRINGS['dverif'])[:KEY_LEN]


def get_next_day_master_key(prev_master_key: bytes, install_day: bool = False) -> bytes:
    if install_day:
        return hmac(prev_master_key, STRINGS['master0'])[:KEY_LEN]
    else:
        return hmac(prev_master_key, STRINGS['master'])[:KEY_LEN]
