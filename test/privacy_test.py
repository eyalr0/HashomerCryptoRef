from HashomerCryptoRef.source.server import Server
from HashomerCryptoRef.source.user import User
from HashomerCryptoRef.source.time import Time, JITTER_THRESHOLD
from HashomerCryptoRef.source.utilities import Contact
from HashomerCryptoRef.source.time import day_to_second


def test_delete_time():
    """
    A test to check that the user can delete data from specific periods.
    Scenario:
        - A, B, C are all created on day 100
        - A contacts B on day 110 (with some gitter in times)
        - A contacts C on day 115 (with some gitter in times)
        - A deletes days 114-116
        - A is diagnosed as infected; sends his keys to the server.
        - The server distributes A's keys to B and C.
    Expected result:
        - B is notified (one contact).
        - C is not notified (zero contacts).
    (positive test)
    """
    id_a = b'\x11j1w\xeao\xb8b\x85\xf8\xfd\x99@^e8'
    id_b = b'\xfaz\xde\x99\x95\xb2\x9c\r\xe0|1g\x9b\xeb\x07/'
    id_c = b'\xba\xea~\x98\r\xd6X\x9c\xf3\xf0\xcdRk5\xe80'

    key_a = b'\xf4\xa4\xec\x1b:\xe6Q\xb4\xbb\xbf\n\xac:\xb8\xc9\xaf'
    key_b = b',_\xb7\xf0\xfa\x9e\xa5\x1f\xd8\xef\xbb&\xe7\xb2\xe0;'
    key_c = b'\x95\t\xec\xce\xae\xbai\x11\x08\x8e\x9b\x94R^1F'

    geohash_ab = b'\xb1\xfd\x88\x84s'
    geohash_ba = b'`z\xb0;H'
    geohash_ac = b'\x8c\xff\x8b\x93\xa2'
    geohash_ca = b'7got%'

    install_time = day_to_second(100)
    contact_ab = day_to_second(110)
    contact_ba = contact_ab + 30
    contact_ac = day_to_second(115)
    contact_ca = contact_ac - 30
    a_delete_from = day_to_second(114)
    a_delete_to = day_to_second(116)

    rssi = None

    user_a = User(id_a, key_a, install_time)
    user_b = User(id_b, key_b, install_time)
    user_c = User(id_c, key_c, install_time)
    server = Server()

    user_a.update_key_databases(install_time, contact_ab)
    ephid_ab = user_a.generate_ephemeral_id(contact_ab, geohash_ab)
    assert user_b.store_contact(ephid_ab, rssi, contact_ba, geohash_ba)

    user_a.update_key_databases(contact_ab, contact_ac)
    ephid_ac = user_a.generate_ephemeral_id(contact_ac, geohash_ac)
    assert user_c.store_contact(ephid_ac, rssi, contact_ca, geohash_ca)

    user_a.delete_my_keys(a_delete_from, a_delete_to)

    # a is infected and sends his keys to the server
    keys_for_distribution = user_a.get_keys_for_server()
    server.receive_user_key(keys_for_distribution)
    server_msg = server.send_keys()

    matches_b = user_b.find_crypto_matches(server_msg)
    matches_c = user_c.find_crypto_matches(server_msg)

    assert len(matches_b) == 1
    assert len(matches_c) == 0

    match = matches_b[0]
    assert match.contact.EphID == ephid_ab
    assert match.contact.time == contact_ba
    assert match.contact.location == geohash_ba
    assert match.contact.RSSI == rssi
    assert match.infected_geohash == geohash_ab
    assert abs(match.infected_time - contact_ab) <= JITTER_THRESHOLD
    assert match.proof == user_a.epoch_keys[Time(contact_ab)].epochVER[:4]


def test_delete_contact():
    """
    A test to check that the user can delete meeting a contact.
    (positive test)
    """
    id_a = bytes([1] + [0] * 15)
    id_b = bytes([2] + [0] * 15)
    id_c = bytes([3] + [0] * 15)

    key_a = bytes(i + 2 for i in range(16))
    key_b = bytes(i + 4 for i in range(16))
    key_c = bytes(i + 5 for i in range(16))

    install_time_a = day_to_second(100)
    install_time_b = install_time_a + 60
    install_time_c = install_time_a + 120

    contact_ab = day_to_second(110)
    contact_ba = day_to_second(110) + 5
    contact_ac = day_to_second(115)
    contact_ca = day_to_second(115) + 5

    rssi = None

    user_a = User(id_a, key_a, install_time_a)
    user_b = User(id_b, key_b, install_time_b)
    user_c = User(id_c, key_c, install_time_c)

    server = Server()

    # first contact.
    user_a.update_key_databases(install_time_a, contact_ab)
    eph_id_ab = user_a.generate_ephemeral_id(contact_ab, bytes([0] * 5))
    assert user_b.store_contact(eph_id_ab, rssi, contact_ba, bytes([0] * 5))

    # second contact.
    user_a.update_key_databases(install_time_a, contact_ac)
    eph_id_ac = user_a.generate_ephemeral_id(contact_ac, bytes([0] * 5))
    assert user_c.store_contact(eph_id_ac, rssi, contact_ca, bytes([0] * 5))

    # user b delete's his contact with user a
    contact = Contact(eph_id_ab, rssi, contact_ba, bytes([0] * 5))
    user_b.delete_contact(contact)

    # sending first user keys to server
    result_keys = user_a.get_keys_for_server()
    server.receive_user_key(result_keys)
    server_msg = server.send_keys()

    second_user_matches = user_b.find_crypto_matches(server_msg)
    third_user_matches = user_c.find_crypto_matches(server_msg)

    assert len(second_user_matches) == 0
    assert len(third_user_matches) == 1

    assert third_user_matches[0].contact.EphID == eph_id_ac
    assert third_user_matches[0].contact.time == contact_ca
    assert third_user_matches[0].contact.location == bytes([0] * 5)
    assert third_user_matches[0].contact.RSSI is None

    assert third_user_matches[0].infected_geohash == bytes([0] * 5)
    assert third_user_matches[0].proof == user_a.epoch_keys[Time(contact_ac)].epochVER[:4]
    assert third_user_matches[0].infected_time == contact_ac


def test_user_delete_past_data():
    """
    A test to check that the user deletes ephemeral data from more then 14 days ago.
    (positive test)
    """
    id_a = bytes([1] + [0] * 15)
    id_b = bytes([2] + [0] * 15)

    key_a = bytes(i + 2 for i in range(16))
    key_b = bytes(i + 4 for i in range(16))

    install_time_a = day_to_second(100)
    install_time_b = day_to_second(101)
    contact_ab = day_to_second(110)
    contact_ba = day_to_second(110) + 5

    rssi = None

    user_a = User(id_a, key_a, install_time_a)
    user_b = User(id_b, key_b, install_time_b)

    server = Server()

    # contact between user a and user b.
    user_a.update_key_databases(install_time_a, contact_ab)
    eph_id_ab = user_a.generate_ephemeral_id(contact_ab, bytes([0] * 5))
    assert user_b.store_contact(eph_id_ab, rssi, contact_ba, bytes([0] * 5))

    # update both users to day 124
    update_time = day_to_second(124)
    user_a.update_key_databases(install_time_a, update_time)
    user_b.update_key_databases(install_time_b, update_time)
    _ = user_a.generate_ephemeral_id(update_time, bytes([0] * 5))
    _ = user_b.generate_ephemeral_id(update_time, bytes([0] * 5))

    # this test is pretty stupid. but the test inside the real application is better.
    # the application will need to call delete history for the past 14 days every time.
    history_time = day_to_second(110) + 6
    user_a.delete_history(history_time)
    user_b.delete_history(history_time)

    # sending first user keys to server
    result_keys = user_a.get_keys_for_server()
    server.receive_user_key(result_keys)
    server_msg = server.send_keys()

    second_user_matches = user_b.find_crypto_matches(server_msg)

    assert len(second_user_matches) == 0


def test_server_delete_past_data():
    """
    A test to check that the user deletes ephemeral data from more then 14 days ago.
    (positive test)
    """
    pass
