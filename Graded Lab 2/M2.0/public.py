from abc import abstractmethod
from typing import Optional, Tuple

from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey


class ECCInterface:
    @classmethod
    @abstractmethod
    def derive_symmetric_keys(
        cls, privkey: EccKey, pubkey: EccKey
    ) -> Tuple[bytes, bytes]:
        pass

    @classmethod
    @abstractmethod
    def encrypt(
        cls, key_enc: bytes, message: bytes, nonce: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        pass

    @classmethod
    @abstractmethod
    def decrypt(
        cls, key_dec: bytes, ciphertext: bytes, tag: bytes, nonce: bytes
    ) -> bytes:
        pass

#server's public key, already with the point P = d G, where G is generator
carpet_pubkey = ECC.construct(
    curve="NIST P-256",
    point_x=13715148733065128759905196296081349018191704649317696632694010920628325175704,
    point_y=76592743378189892955944002062779358926630431132311995073049838517480178060535,
)
#this coordinates are the public key;

# Test keys for running the server locally.
carpet_test_privkey = ECC.construct(curve="NIST P-256", d=1337)
carpet_test_pubkey = carpet_test_privkey.public_key()
