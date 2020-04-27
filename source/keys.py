from typing import List, Tuple
from .crypto import hmac_sha256 as hmac
from .crypto import encrypt
from .bytes_utils import num_to_bytes, STRINGS
from .derivation_utils import get_key_commit_i, get_key_epoch

KEY_LEN = 16
MESSAGE_LEN = 16
HMAC_KEY_LEN = 64


# Represents a set of keys an infected user sends to the server
# Keys are stored as tupples: (day, epoch, PreK_epoch)
class UserKey:
    def __init__(self, user_id: bytes, key_id: bytes,
                 pre_epochs: List[Tuple[int, int, bytes]], key_master_verification: bytes):
        """
        User key of infected users. should be sent to the server if an infected user agrees.

        :param user_id:                     user id.
        :param key_id:                      Identification key
        :param pre_epochs:                  cryptographic keys for users to check for contact.
        :param key_master_verification:     key for validating user.
        """
        self.ID = user_id
        self.K_ID = key_id
        self.preEpoch = pre_epochs
        self.K_masterVER = key_master_verification


class DayKey:
    def __init__(self, i: int, master_key: bytes, key_master_com: bytes, key_master_verification: bytes):
        """
        Day key to derive epoch keys from.

        :param i:                           The corresponding day
        :param master_key:                  The current day master key. Use get_next_master_key.
        :param key_master_com:              The master commitment key.
        :param key_master_verification:     Master verification key for proofing id.
        """
        self.day = hmac(master_key, STRINGS['ddaykey'])[:KEY_LEN]
        self.verification = hmac(key_master_verification, num_to_bytes(i, 4) + STRINGS['dverif'])[:KEY_LEN]
        self.commit = get_key_commit_i(key_master_com, num_to_bytes(i, 4))


class EpochKey:
    def __init__(self, i: int, j: int, k_day: DayKey):
        """
        Key for a specific epoch.

        :param i:           epoch day.
        :param j:           epoch index
        :param k_day:       day key.
        """
        time_prefix = num_to_bytes(i, 4) + num_to_bytes(j, 1)
        self.preKey = encrypt(k_day.day, time_prefix + b'\x00'*11)
        self.epoch = get_key_epoch(self.preKey, k_day.commit, num_to_bytes(i, 4), num_to_bytes(j, 1))
        self.epochENC = encrypt(self.epoch, time_prefix + b'\x00'*11)
        self.epochMAC = encrypt(self.epoch, time_prefix + b'\x01' + b'\x00'*10)
        self.epochVER = encrypt(k_day.verification, time_prefix + b'\x00'*11)
