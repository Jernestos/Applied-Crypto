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


customer_service_pubkey = ECC.construct(
    curve="NIST P-256",
    point_x=77268342261805963459463921904248533821169311525188769991007136345111192041220,
    point_y=38355973832426445626591252985005104275138174232649807405805296651148692703102,
)

carpet_pubkey = ECC.construct(
    curve="NIST P-256",
    point_x=34801737268792676687660691881746525396617498675566538490685444269434064726836,
    point_y=74057785728038313498956920233734149587764452770253153077441576986754902980651,
)

# Test keys for running the server locally.
carpet_test_privkey = ECC.construct(curve="NIST P-256", d=1337)
carpet_test_pubkey = carpet_test_privkey.public_key()
