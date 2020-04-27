from HashomerCryptoRef.source.time import day_to_second, T_UNIT
from HashomerCryptoRef.source.user import User


def dos_test():
    """
    Test 1 in section 6(spam prevention).
    sending many BLE in short time.
    user should only accept 1000.
    """

    id_a = bytes([1] + [0] * 15)
    id_b = bytes([2] + [0] * 15)
    id_c = bytes([3] + [0] * 15)
    id_d = bytes([4] + [0] * 15)
    id_e = bytes([5] + [0] * 15)
    key_a = bytes(i + 2 for i in range(16))
    key_b = bytes(i + 3 for i in range(16))
    key_c = bytes(i + 4 for i in range(16))
    key_d = bytes(i + 5 for i in range(16))
    key_e = bytes(i + 6 for i in range(16))

    install_time = day_to_second(100)

    rssi = None
    geo_hash = bytes([0] * 5)

    user_a = User(id_a, key_a, install_time)
    user_b = User(id_b, key_b, install_time)
    user_c = User(id_c, key_c, install_time)
    user_d = User(id_d, key_d, install_time)
    user_e = User(id_e, key_e, install_time)

    counter = 0
    for i in range(T_UNIT):
        time = install_time + i

        eph_b = user_b.generate_ephemeral_id(time, geo_hash)
        eph_c = user_c.generate_ephemeral_id(time, geo_hash)
        eph_d = user_d.generate_ephemeral_id(time, geo_hash)
        eph_e = user_e.generate_ephemeral_id(time, geo_hash)

        if counter < 1000:
            assert user_a.store_contact(eph_b, rssi, time, geo_hash)
            assert user_a.store_contact(eph_c, rssi, time, geo_hash)
            assert user_a.store_contact(eph_d, rssi, time, geo_hash)
            assert user_a.store_contact(eph_e, rssi, time, geo_hash)
        else:
            assert not user_a.store_contact(eph_b, rssi, time, geo_hash)
            assert not user_a.store_contact(eph_c, rssi, time, geo_hash)
            assert not user_a.store_contact(eph_d, rssi, time, geo_hash)
            assert not user_a.store_contact(eph_e, rssi, time, geo_hash)
        counter += 4

    assert len(user_a.contacts) == 1000

    user_b.update_key_databases(install_time, install_time + day_to_second(3))
    eph_b = user_b.generate_ephemeral_id(install_time + day_to_second(3), geo_hash)
    assert user_a.store_contact(eph_b, rssi, install_time + day_to_second(3), geo_hash)

    assert len(user_a.contacts) == 1001
