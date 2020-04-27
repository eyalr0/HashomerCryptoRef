from __future__ import annotations


# All time constants are in seconds
T_DAY = 24*60*60
# 1 hour
T_EPOCH = 60 * 60
T_UNIT = 5 * 60
UNITS_IN_EPOCH = T_EPOCH // T_UNIT
JITTER_THRESHOLD = 10 * 60
EPOCHS_IN_DAY = T_DAY // T_EPOCH
T_WINDOW = 5 * 60
MAX_CONTACTS_IN_WINDOW = 1000


def day_to_second(day: int) -> int:
    return T_DAY * day


class Time:
    def __init__(self, unix_time: int, epoch: int = None):
        if epoch is None:
            self.time = unix_time
            self.day = unix_time // T_DAY
            self.epoch = (unix_time % T_DAY) // T_EPOCH
        else:
            assert epoch < EPOCHS_IN_DAY, "Epoch ({}) must be < {}".format(epoch, EPOCHS_IN_DAY)
            self.day = unix_time
            self.epoch = int(epoch)

    def get_units(self) -> int:
        return (self.time - self.day*T_DAY - self.epoch * T_EPOCH) // T_UNIT

    def get_next(self) -> Time:
        if self.epoch == EPOCHS_IN_DAY-1:
            return Time(self.day+1, 0)
        return Time(self.day, self.epoch+1)

    def str_with_units(self) -> str:
        # for hashing-including-unit purposes
        return "{}-{}-{}".format(self.day, self.epoch, self.get_units())

    def __hash__(self) -> hash:
        return hash((self.day, self.epoch))

    def __eq__(self, other: Time) -> bool:
        return self.day == other.day and self.epoch == other.epoch

    def __ne__(self, other: Time) -> bool:
        return not(self == other)

    def __lt__(self, other: Time) -> bool:
        return EPOCHS_IN_DAY*self.day + self.epoch < EPOCHS_IN_DAY*other.day + other.epoch

    def __le__(self, other: Time) -> bool:
        return EPOCHS_IN_DAY*self.day + self.epoch <= EPOCHS_IN_DAY*other.day + other.epoch

    def __gt__(self, other: Time) -> bool:
        return EPOCHS_IN_DAY*self.day + self.epoch > EPOCHS_IN_DAY*other.day + other.epoch

    def __ge__(self, other: Time) -> bool:
        return EPOCHS_IN_DAY*self.day + self.epoch >= EPOCHS_IN_DAY*other.day + other.epoch
