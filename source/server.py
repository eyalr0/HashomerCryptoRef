"""
    for complaints: Ron Asherov
"""

from .keys import UserKey
from .bytes_utils import num_to_bytes
from .crypto import encrypt
from .derivation_utils import get_key_master_com, get_key_commit_i, get_key_epoch, get_key_i_verification

USER_RAND_LEN = 4


# note that no identification data is stored on the server.
# The keys are identified only using the MoH generated TestCode.
class Server:
    def __init__(self):
        # self.epochs[day][epoch] = [randomized list of (epoch key, verification key)]
        self.epochs = {}

    def receive_user_commit(self, user_commit_id, user_key_id, test_code):
        pass

    def receive_user_key(self, user_key: UserKey) -> None:
        """
        Receive a key from an infected user key who agreed to send his keys.

        :param user_key:
        :return:
        """
        # TODO get a test code and verify it against ID
        key_com_master = get_key_master_com(user_key.K_ID, user_key.ID)
        # From this point, we will no longer need K_ID nor ID. These values should be deleted.
        del user_key.K_ID, user_key.ID

        key_master_verification = user_key.K_masterVER
        key_com_daily = {}

        for day, epoch, k_pre_epoch in user_key.preEpoch:
            if day not in self.epochs:
                self.epochs[day] = {}
            if epoch not in self.epochs[day]:
                self.epochs[day][epoch] = []

            daily_commit_key = key_com_daily.setdefault(day, get_key_commit_i(key_com_master, num_to_bytes(day, 4)))
            epoch_key = get_key_epoch(k_pre_epoch, daily_commit_key, num_to_bytes(day, 4), num_to_bytes(epoch, 1))
            daily_verification_key = get_key_i_verification(key_master_verification, day)
            epoch_ver = encrypt(daily_verification_key, num_to_bytes(day, 4) + num_to_bytes(epoch, 1) + b'\x00'*11)

            self.epochs[day][epoch].append((epoch_key, epoch_ver))

            # randomize the order
            self.epochs[day][epoch] = sorted(self.epochs[day][epoch], key=lambda x: x[0])

    def send_keys(self) -> dict:
        # TODO some kind of delete-old-keys mechanism
        epochs = {}
        for day in self.epochs.keys():
            epochs[day] = {}
            for epoch in self.epochs[day].keys():
                epochs[day][epoch] = [x[0] for x in self.epochs[day][epoch]]
        return epochs

    def verify_contact(self, day: int, epoch: int, proof: bytes):
        """

        :note           if proof is correct, self.epochs[day][epoch] should contain a tuple (epoch_key, epoch_ver)
                        such that epoch_ver's first four bytes are proof
        :param day:
        :param epoch:
        :param proof:
        :return:
        """
        return any([x[1][:USER_RAND_LEN] == proof for x in self.epochs.get(day, {}).get(epoch, [])])
