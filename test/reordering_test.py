from HashomerCryptoRef.source.time import T_DAY
from HashomerCryptoRef.source.user import User
from HashomerCryptoRef.source.server import Server
from HashomerCryptoRef.source.utilities import Contact


def day_to_seconds(day):
    return T_DAY * day


def test_ordering():
    """
    A test to check that the BLE messages are sorted by time.
    """

    id_a = bytes([1] + [0] * 15)
    id_b = bytes([2] + [0] * 15)
    id_c = bytes([3] + [0] * 15)
    id_d = bytes([4] + [0] * 15)
    key_a = bytes(i + 2 for i in range(16))
    key_b = bytes(i + 4 for i in range(16))
    key_c = bytes(i + 6 for i in range(16))
    key_d = bytes(i + 28 for i in range(16))

    geo_hash = bytes([0] * 5)
    rssi = None

    install_time_a = day_to_seconds(100)
    install_time_b = day_to_seconds(100) + 100
    install_time_c = day_to_seconds(101)
    install_time_d = day_to_seconds(101) + 100

    contact_first_ba = day_to_seconds(105) + 10
    contact_ca = day_to_seconds(105) + 11
    contact_second_ba = day_to_seconds(109)
    contact_da = day_to_seconds(110)

    contact_first_ab = day_to_seconds(105) + 15
    contact_ac = day_to_seconds(105) + 14
    contact_second_ab = day_to_seconds(109) + 5
    contact_ad = day_to_seconds(110) + 5

    contacts = []

    user_a = User(id_a, key_a, install_time_a)
    user_b = User(id_b, key_b, install_time_b)
    user_c = User(id_c, key_c, install_time_c)
    user_d = User(id_d, key_d, install_time_d)

    # contact between a and b
    user_b.update_key_databases(install_time_b, contact_first_ba)
    eph_id_first_ba = user_b.generate_ephemeral_id(contact_first_ba, geo_hash)
    assert user_a.store_contact(eph_id_first_ba, rssi, contact_first_ab, geo_hash)
    contacts.append(Contact(eph_id_first_ba, rssi, contact_first_ab, geo_hash))

    assert user_a.contacts == contacts

    # contact between a and c(will not be accepted because it is in the past).
    user_c.update_key_databases(install_time_c, contact_ca)
    eph_id_ca = user_c.generate_ephemeral_id(contact_ca, geo_hash)
    assert user_a.store_contact(eph_id_ca, rssi, contact_ac, geo_hash)
    contacts.append(Contact(eph_id_ca, rssi, contact_ac, geo_hash))

    # contact between a and b
    user_b.update_key_databases(install_time_b, contact_second_ba)
    eph_id_second_ba = user_b.generate_ephemeral_id(contact_second_ba, geo_hash)
    assert user_a.store_contact(eph_id_second_ba, rssi, contact_second_ab, geo_hash)
    contacts.append(Contact(eph_id_second_ba, rssi, contact_second_ab, geo_hash))

    # contact between a and b
    user_d.update_key_databases(install_time_d, contact_da)
    eph_id_da = user_d.generate_ephemeral_id(contact_da, geo_hash)
    assert user_a.store_contact(eph_id_da, rssi, contact_ad, geo_hash)
    contacts.append(Contact(eph_id_da, rssi, contact_ad, geo_hash))

    # Python only sorted contact's of find_crypto_matches function.
    assert len(user_a.find_crypto_matches({})) == 0
    assert user_a.contacts[0].time < user_a.contacts[1].time < user_a.contacts[2].time < user_a.contacts[3].time


def test_ordering_server():
    """
    Test 2 of section 5 - Ordering.
    Server gets 100 messages from users,
    all of them sent keys belonging to a specific epoch.
    """

    users_id = [bytes([i] * 16) for i in range(100)]
    users_key = [bytes([i + 3] * 16) for i in range(100)]
    install_time = day_to_seconds(100)

    users = [User(users_id[i], users_key[i], install_time) for i in range(100)]

    server = Server()

    for i in range(100):
        users[i].update_key_databases(install_time + i, install_time + i + 1)

    for i in range(100):
        keys = users[i].get_keys_for_server()
        server.receive_user_key(keys)

    server_message = server.send_keys()

    for day in server_message.keys():
        for epoch in server_message[day].keys():
            assert sorted(server_message[day][epoch]) == server_message[day][epoch]
