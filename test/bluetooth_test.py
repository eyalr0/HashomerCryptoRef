from HashomerCryptoRef.source.user import User
from HashomerCryptoRef.source.server import Server
from HashomerCryptoRef.source.time import Time, day_to_second


def test_key_derivation():
    """
    General test for the key derivation.
    (positive test)
    """
    user_id = b'n\xb3\x1aqy\x8bF\xe3\x98\xee\x01X\x1b\x8cp\xc6'
    master_key = b'3>\xa5\xce\xd8\xf42\xdc\x83\xb7)\xcd\xc6\xa8\x91D'
    # day = 18374
    time = 1587592647
    target_day = 18401

    exp_master_com = b'\x15a\xaf\xac\t\xfbdl\x1dF\xc5\xdaj\x96\x8e\xa4'
    exp_day_master = b'\x8d\x99E\x92\xa0\x95J\x1fa\xed\x85\xeaZ\xc8\x99f'
    exp_k_day = b'\x80{\x14j\xc4?.\xb9\xa2<+\x9a\x85\x8f\xd9\xd2'
    exp_verification_key = b'\x93zWF\xb6Ko\xb9x-"\xe5g\xf2,<'
    exp_k_id = b'\xa0Bv\xd9Q\x08*\x7f\xea\xc7\xb1\xfe?\x02D\x0b'
    exp_k_master_ver = b'\x12J-l\x02V\xefu\x93k\xf3\t*k\xa6e'

    user = User(user_id, master_key, time)
    assert user.K_master_com == exp_master_com
    assert user.K_id == exp_k_id
    assert user.K_master_ver == exp_k_master_ver
    # TODO [RA] change this to an epoch key check
    #           or to a check on the DayKey function itself

    # k = user._get_day_key(target_day)
    # assert user.curr_day_master_key == exp_day_master
    # assert k.day == exp_k_day
    # assert k.verification == exp_verification_key


def test_ephid():
    """
    test the generating epemeral id's.
    (positive test)
    """
    user_id = b'\x81\x87S\x06\x04\xc6.I\xf3\x84\xb9\x189\xe8K\xd3'
    master_key = b'\x84&,\xd3C\xb1\xee\x86\xbb\xbe\xb4\x03\xdabM\xf9'
    # day = 18374
    time = 1587592647
    geohash = b'\xb4\xf2\xd5\x1d\x7f'
    target_time = int(time + 60*60*26.5)

    expected_ephid = b'\xc8>A\xc5\x1a\x95\xb3\xeaN\x83\x96\xab\xb4/6A'

    user = User(user_id, master_key, time)
    user.update_key_databases(time, target_time)
    assert user.generate_ephemeral_id(target_time, geohash) == expected_ephid


def test_contact_then_verify():
    """
    default test for two user's that were in contact.
    (positive test)
    """

    first_user_id = b'carolefuknbaskin'
    first_user_key = b'0\xe7\x9f\x91\xaa$\x1eB\x94\xe7fX\x82\xf0\xff\xe7'
    # day = 18374
    first_user_init_time = 1587592647
    second_user_id = b'___joe_exotic___'
    second_user_key = b'\xd9\x1d\x1eP\x8a\xb8\\:\x8d\xc8^\x02\xa7|\xb1='
    second_user_init_time = int(first_user_init_time + 60*60*24*3.5)
    first_user_contact_time = int(second_user_init_time + 60*60*24*1.5)
    second_user_contact_time = first_user_contact_time + 100
    first_user_geohash = b'\x81\xd5\x8d\x1f\xf5'
    second_user_geohash = b'9\x19\x04\xa1\x93'
    rssi = None

    expected_proof = b'\xc7x6\x97'

    first_user = User(first_user_id, first_user_key, first_user_init_time)
    second_user = User(second_user_id, second_user_key, second_user_init_time)
    server = Server()

    first_user.update_key_databases(first_user_init_time, first_user_contact_time)
    eph_id = first_user.generate_ephemeral_id(first_user_contact_time, first_user_geohash)
    assert second_user.store_contact(eph_id, rssi, second_user_contact_time, second_user_geohash)

    server_keys_a = first_user.get_keys_for_server()
    server.receive_user_key(server_keys_a)
    server_msg = server.send_keys()

    matches = second_user.find_crypto_matches(server_msg)
    assert len(matches) == 1, "Expected one match, found {}".format(len(matches))
    m = matches[0]
    assert m.proof == expected_proof
    assert m.infected_geohash == first_user_geohash

    t1 = Time(first_user_contact_time)
    t2 = Time(m.infected_time)
    assert t1.day == t2.day and t1.epoch == t2.epoch and t1.get_units() == t2.get_units()

    # Make sure the server validates the match
    assert server.verify_contact(t2.day, t2.epoch, m.proof)


def test_updating_database():
    """
    unit test for the update_database function.
    checking the update_key_database delete past time.
    """
    id_a = bytes([1] + [0] * 15)
    key_a = bytes(i + 2 for i in range(16))

    install_time = day_to_second(100)

    user_a = User(id_a, key_a, install_time)

    user_a.update_key_databases(day_to_second(99), day_to_second(113))
    user_a.update_key_databases(day_to_second(110), day_to_second(115))

    assert min(user_a.epoch_keys.keys()) == Time(day_to_second(110))
