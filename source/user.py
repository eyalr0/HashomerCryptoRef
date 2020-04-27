"""
    for complaints: Ron Asherov
"""

from typing import List, Tuple
from .utilities import Match, Contact
from .bytes_utils import num_to_bytes, xor, STRINGS
from .keys import UserKey, DayKey, EpochKey, KEY_LEN, MESSAGE_LEN
from .derivation_utils import get_key_master_com, get_epoch_keys, get_next_day_master_key
from .crypto import encrypt
from .crypto import hmac_sha256 as hmac
from .time import Time, T_UNIT, JITTER_THRESHOLD, EPOCHS_IN_DAY, MAX_CONTACTS_IN_WINDOW, T_WINDOW


USER_RAND_LEN = 4
GEOHASH_LEN = 5


class User:
    def __init__(self, user_id: bytes, master_key: bytes, init_time: int):
        self.user_id = user_id[:]

        self.K_id = hmac(master_key, STRINGS['id'])[:KEY_LEN]
        self.K_master_com = get_key_master_com(self.K_id, self.user_id)
        self.K_master_ver = hmac(master_key, STRINGS['verifkey'])[:KEY_LEN]
        self.epoch_keys = {}
        self.contacts = []
        self.curr_day = Time(init_time).day
        self.curr_day_master_key = get_next_day_master_key(master_key, install_day=True)
        self._get_epoch_keys(self.curr_day)

    def update_key_databases(self, past_time: int, future_time: int) -> None:
        """
        Update the key database to store key's of specific time intreval.
        To protect the user's privacy, all information (including contact information)
        older than past_time will be deleted.

        :param past_time:   start time to store keys(should be a time from the past).
                            All stored keys before past_time will be deleted.
        :param future_time: end time to store keys(should be a time from the future).

        :return:
        """
        past = Time(past_time)
        future = Time(future_time)

        self._get_epoch_keys(future.day)
        self.delete_history(past.time)

    def generate_ephemeral_id(self, time: int, geo_hash: bytes) -> bytes:
        """
        Generate the ephemeral id of a specific time. User should have the right epoch keys.

        :param time:        current time.
        :param geo_hash:    current location.
        :return:            The ephemeral id.
                            Raises an error if epoch keys are not present.
        """
        assert len(geo_hash) == GEOHASH_LEN
        t = Time(time)
        assert t in self.epoch_keys.keys(), "Epoch key is not present"
        time_unit_s = t.get_units()
        epoch_key = self.epoch_keys[t]

        mask = encrypt(epoch_key.epochENC, num_to_bytes(time_unit_s, MESSAGE_LEN))
        user_rand = epoch_key.epochVER[:USER_RAND_LEN]

        plain = b'\x00'*3 + geo_hash + user_rand + b'\x00'*4
        c_ijs = xor(plain, mask)
        return c_ijs[:12] + encrypt(epoch_key.epochMAC, c_ijs)[:4]

    def find_crypto_matches(self, infected_key_database: dict) -> List[Match]:
        """
        Check for matching with the infected user.
        :param infected_key_database:
        :return: List of matches with the infected user.
        """
        matches = []

        # Make sure the contacts are sorted so as to make the sliding window work properly
        self.contacts = sorted(self.contacts, key=lambda c: c.time)

        # domain is a time up to units (actually a string "day-epoch-unit")
        # and its range is a list of (mask, epochMAC)
        unit_keys = {}
        earliest_time = None
        for contact in self.contacts:
            time = contact.time - JITTER_THRESHOLD

            # Remove all entries unit_keys[t] for t < time (will save memory usage)
            # For it to work we need self.contact to be ordered by contact.time
            if earliest_time is not None:
                while earliest_time < time:
                    t_dict_key = Time(earliest_time).str_with_units()
                    if t_dict_key in unit_keys.keys():
                        del unit_keys[t_dict_key]
                    earliest_time += T_UNIT
            else:
                earliest_time = time

            while time <= contact.time + JITTER_THRESHOLD:
                t = Time(time)
                t_key = t.str_with_units()
                unit = t.get_units()
                time += T_UNIT

                if t_key not in unit_keys:
                    unit_keys[t_key] = []
                    for epoch_key in infected_key_database.get(t.day, {}).get(t.epoch, []):
                        epoch_enc, epoch_mac = get_epoch_keys(epoch_key, t.day, t.epoch)
                        mask = encrypt(epoch_enc, num_to_bytes(unit, MESSAGE_LEN))
                        unit_keys[t_key].append((mask, epoch_mac))

                for mask, epoch_mac in unit_keys[t_key]:
                    match = self._is_match(mask, epoch_mac, contact)
                    if match[0]:
                        matches.append(Match(contact, match[1], match[2], t, unit))

        return matches

    def delete_my_keys(self, start_time: int, end_time: int) -> None:
        """
        Delete my keys in a time period.
        :param start_time:              start time of period to delete.
        :param end_time:                end time of period to delete.
        :note:                          only deleting key and not contacts.
        :return:
        """
        start = Time(start_time)
        end = Time(end_time)

        # TODO [RA]: what if end_time is in the future?

        epoch_keys_to_delete = []

        for time in self.epoch_keys.keys():
            if start <= time <= end:
                epoch_keys_to_delete.append(time)

        for key in epoch_keys_to_delete:
            del self.epoch_keys[key]

    def get_keys_for_server(self) -> UserKey:
        """
        Get a willing infected user keys.
        The keys will be sent to all user by the server.

        :return: Keys to be sent to the server.
        """
        # TODO I assume all currently existing keys are relevant.
        # Perhaps a 'checkup' is needed, i.e. remove old keys and so.
        # TODO similarly, one needs to make sure all non-deleted epoch keys
        #  are in self.epoch_keys (i.e. they were, at some point, derived from the daily key)
        # TODO current version only sends epochs, i.e. does not try to reduce bandwidth by sending daily keys.

        epochs = [(T.day, T.epoch, self.epoch_keys[T].preKey) for T in self.epoch_keys.keys()]
        keys = UserKey(self.user_id, self.K_id, epochs, self.K_master_ver)
        return keys

    def store_contact(self, other_ephemeral_id: bytes, rssi, time: int, own_location: bytes) -> bool:
        """
        Store an ephemeral id from BLE received in the wild.

        :param other_ephemeral_id:  other user ephemeral id.
        :param rssi:                ?
        :param time:                current time.
        :param own_location:        current location
        :return:                    None.
        """
        if len(self.contacts) > 0 and time < self.contacts[-1].time - JITTER_THRESHOLD:
            # We expect contacts to come in chronological order
            # Up to jitter
            return False
        if len(self.contacts) >= MAX_CONTACTS_IN_WINDOW:
            past_contact_time = self.contacts[-MAX_CONTACTS_IN_WINDOW].time
            if time - past_contact_time < T_WINDOW:
                # If there have been too many contacts in this epoch, ignore this contact.
                return False
        self.contacts.append(Contact(other_ephemeral_id, rssi, time, own_location))
        return True

    def delete_contact(self, contact: Contact) -> None:
        """
        deletes a contact from local contact DB.

        :param contact: Contact to delete.
        :return:
        """
        self.contacts = [x for x in self.contacts if x != contact]

    def delete_history(self, dtime: int) -> None:
        """
        Delete all history before a specific time.
        Should be used also to delete days that are more then 14 days in the past.

        :param dtime:   time to delete history from
        :note:          deleting all keys and contacts.
        :return:
        """
        # Deletes all local information for time < dtime.
        # This include all keys and contacts.
        t = Time(dtime)

        self.epoch_keys = {x: y for x, y in self.epoch_keys.items() if x >= t}
        self.contacts = [x for x in self.contacts if x.time >= dtime]

    def _get_epoch_keys(self, target_day: int) -> None:
        """
        Makes sure the user has all epoch keys corresponding to a given day
        :param target_day:     day to update.
        :return:
        """
        # If all keys are present, nothing to be done.
        if all([Time(target_day, epoch) in self.epoch_keys.keys() for epoch in range(EPOCHS_IN_DAY)]):
            return
        # Else, we need to generate keys.
        assert self.curr_day <= target_day, "Cannot retrieve keys from the past"
        while self.curr_day <= target_day:
            curr_day_key = DayKey(self.curr_day, self.curr_day_master_key,
                                  self.K_master_com, self.K_master_ver)
            for epoch in range(EPOCHS_IN_DAY):
                self.epoch_keys[Time(self.curr_day, epoch)] = EpochKey(self.curr_day, epoch, curr_day_key)

            self.curr_day += 1
            self.curr_day_master_key = get_next_day_master_key(self.curr_day_master_key, install_day=False)

    @staticmethod
    def _is_match(mask: bytes, epoch_mac: bytes, contact: Contact) -> Tuple[bool, bytes, bytes]:
        ephid = contact.EphID
        plain = xor(mask, ephid)
        zeros = plain[:3]
        ephid_geohash = plain[3:3 + GEOHASH_LEN]
        ephid_user_rand = plain[3 + GEOHASH_LEN:3 + GEOHASH_LEN + USER_RAND_LEN]

        # First three bytes of plaintext are zero
        if any([x != 0 for x in zeros]):
            return False, bytes(0), bytes(0)

        x = ephid[:-4] + mask[-4:]
        y = ephid[-4:]
        if y == encrypt(epoch_mac, x)[:4]:
            return True, ephid_geohash, ephid_user_rand
        return False, bytes(0), bytes(0)
