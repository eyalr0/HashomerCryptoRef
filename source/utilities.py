from __future__ import annotations
from .keys import MESSAGE_LEN
from .time import Time, T_DAY, T_EPOCH, T_UNIT


class Match:
    def __init__(self, contact: Contact, ephid_geohash: bytes,
                 ephid_user_rand: bytes, other_time: Time, other_unit: int):
        """

        :param contact:             Contact with the other user.
        :param ephid_geohash:       Other user ephemeral id.
        :param ephid_user_rand:     Other user proof.
        :param other_time:          Other user epoch time of contact.
        :param other_unit:          Other user time unit.
        """
        self.contact = contact
        self.infected_geohash = ephid_geohash
        self.proof = ephid_user_rand
        # Up to T_UNIT
        self.infected_time = other_time.day * T_DAY + other_time.epoch * T_EPOCH + other_unit * T_UNIT


class ContactDB:
    def __init__(self):
        pass


class Contact:
    def __init__(self, ephemeral_id: bytes, rssi, time: int, location: bytes):
        """
        A contact which was sent the user a BLE message.

        :param ephemeral_id:    The contact ephemeral id.
        :param rssi:            Good question. my name contains covid but I don't know everything(covid6Pi).
        :param time:            Time of contact as recorded by the receiving user.
        :param location:        Location of user contact when BLE message received.
        """
        assert len(ephemeral_id) == MESSAGE_LEN
        self.EphID = ephemeral_id
        self.RSSI = rssi
        self.time = time
        self.location = location

    def __eq__(self, other: Contact) -> bool:
        return self.EphID == other.EphID and \
               self.RSSI == other.RSSI and \
               self.time == other.time and \
               self.location == other.location
