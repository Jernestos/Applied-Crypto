from Crypto.PublicKey import ECC

server_privkey = ECC.construct(
    curve="NIST P-256", d=1970926356434545168642438303411891975166503568441911440997
)

server_pubkey = server_privkey.public_key()

client_privkey = ECC.construct(
    curve="NIST P-256",
    d=504702780838107536967954000046221133898156969510434636216353145888531827,
)

client_pubkey = client_privkey.public_key()

# hashed_repr_1 = SHA-256(ecc_point_to_bytes(server_pubkey))
#
# (The SHA-256 step is to avoid leaking how the ecc_point_to_bytes should be
# implemented. You should NOT hash the points in your implementation to obtain
# the point representation in bytes)
hashed_repr_1 = b"\x7f,\x0cn\x0f1S4\xea\xb1s\x8c\xfb\x9a\x94\xd8\x9e.[\xf1\xec\xed\xb6\xf2yad#\x82\xe0\x15="

# hashed_repr_2 = SHA-256(ecc_point_to_bytes(client_pubkey))
#
# (The SHA-256 step is to avoid leaking how the ecc_point_to_bytes should be
# implemented. You should NOT hash the points in your implementation to obtain
# the point representation in bytes)
hashed_repr_2 = b"\xf0(`\xc3\xee\xb7F\x01\x84\xd8@\x9d\x88\xf3E\x93\xf5\xc4q\xbbh\xef^\x1e\x0c\xae~\xcapT\xde\xc7"


# derive_symmetric_keys(server_privkey, client_pubkey) = (key_1, key_2)
# derive_symmetric_keys(client_privkey, server_pubkey) = (key_2, key_1)
key_1 = b"\xb8%\\d\xe9\xd6\xd8J\x9f[Q\xaf\x0f\x9d\xb1\xe9\xcf\xb9\x9b\xd6:\xaf46\xb0\xe85=\xca\xc8\x0ea"
key_2 = b"\x01\x15\xd2\x9a\xb4\xe3R\xe3}Q@hi\xf6j@O\xfa\xb9'\xf1\xd0\x7f\xf07\xb2\xf0\xd1M\xae}\x9f"
