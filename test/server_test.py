from HashomerCryptoRef.source.user import User
from HashomerCryptoRef.source.server import Server
from HashomerCryptoRef.source.time import day_to_second


def duplicate_message_test():
    """
    A test to check that the server only accepts one set of keys from infected user.
    (negative test)
    """
    # TODO the code doesn't support this test. there is no way to check the same user again right know.
    id_a = bytes([1] + [0] * 15)
    key_a = bytes(i + 2 for i in range(16))
    install_time_a = day_to_second(100) + 50
    user_a = User(id_a, key_a, install_time_a)

    server = Server()

    first_contact = day_to_second(102)
    second_contact = day_to_second(104)

    _ = user_a.generate_ephemeral_id(first_contact, bytes([0] * 5))

    # sending first user keys to server
    first_keys = user_a.get_keys_for_server()
    server.receive_user_key(first_keys)
    _ = server.send_keys()

    _ = user_a.generate_ephemeral_id(second_contact, bytes([0] * 5))

    # sending second user keys to server(duplicate send)
    second_keys = user_a.get_keys_for_server()
    server.receive_user_key(second_keys)
    _ = server.send_keys()
