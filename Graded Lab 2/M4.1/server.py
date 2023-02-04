#!/usr/bin/env python3
import json
import sys
from typing import BinaryIO

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes, random

PORT = 51041

"""
It's great that you don't need to understand cryptography for non-security critical
functionalities like backups!
"""


class SmartCarpet:
    def __init__(
        self, key: RSA.RsaKey, cloud_key: RSA.RsaKey, config_key: bytes, flag: str
    ):
        self.skey = key
        self.factory_skey = key
        self.flag = flag
        self.config_key = config_key
        self.trusted_entities = {
            "carpet": self.skey,
            "carpet_cloud": cloud_key,
        }
        self.warranty_void = False

    def get_status(self) -> str:
        dust_lev = random.randint(1, 10000)
        msg = f"There's an awful lot of dust on your carpet: {dust_lev}kg"

        return msg

    def get_flag(self) -> str:
        if self.warranty_void:
            return "No"

        return self.flag

    def save_config(self):
        key = self.skey

        pub_cfg = key.n, key.e
        priv_cfg = "\n".join([str(el) for el in (key.d, key.p, key.q, key.u)]).encode()

        cipher = AES.new(self.config_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(priv_cfg)

        priv_cfg = (cipher.nonce, ciphertext, tag)

        return pub_cfg, priv_cfg

    def restore_config(self, pub_cfg, priv_cfg):
        self.warranty_void = True

        n, e = pub_cfg
        nonce, ciphertext, tag = priv_cfg

        cipher = AES.new(self.config_key, AES.MODE_GCM, nonce=nonce)
        priv_cfg = cipher.decrypt_and_verify(ciphertext, tag)
        d, p, q, u = [int(el) for el in priv_cfg.decode().split()]

        self.skey = RSA.construct((n, e, d, p, q, u), consistency_check=False)

        return "ok"

    def factory_config(self):
        self.warranty_void = False
        self.skey = self.factory_skey

        return "ok"

    def exec_command(self, msg: dict) -> dict:
        """Handles commands.

        Args:
            msg (dict): the command to be handled

        Returns:
            dict: a dictionary representing JSON response.
        """

        command = msg["command"]

        match command:
            case "get_status":
                return {"status": self.get_status()}
            case "save_config":
                pub_cfg, priv_cfg = self.save_config()

                n, e = pub_cfg
                nonce, ciphertext, tag = priv_cfg

                return {
                    "pub_cfg": {"n": n, "e": e},
                    "priv_cfg": {
                        "nonce": nonce.hex(),
                        "ciphertext": ciphertext.hex(),
                        "tag": tag.hex(),
                    },
                }
            case "restore_config":
                pub_cfg, priv_cfg = msg["pub_cfg"], msg["priv_cfg"]

                res = self.restore_config(
                    (pub_cfg["n"], pub_cfg["e"]),
                    (
                        bytes.fromhex(priv_cfg["nonce"]),
                        bytes.fromhex(priv_cfg["ciphertext"]),
                        bytes.fromhex(priv_cfg["tag"]),
                    ),
                )#res = "ok"
                return {"res": res}
            case "factory_config":
                return {"res": self.factory_config()}
            case "backdoor":
                return {"res": self.get_flag()}
            case _:
                return {
                    "error": "The command you tried to execute "
                    "was not recognized: " + command
                }

    def exec_command_secure(self, signed_msg: dict) -> dict:
        """Wraps exec_command with a layer of signature.

        Takes as input a json dictionary, containing:
        msg:          a dictionary representing command
        id:           the identity of the signer
        signature:    RSA PKCS1-v1.5-style signature of the command
        The signature format is described in the client skeleton.

        Args:
            signed_msg (dict): the command to be handled

        Returns:
            dict: a dictionary representing JSON signed response.
        """

        msg = signed_msg["msg"]
        signature = bytes.fromhex(signed_msg["signature"])
        # Pick the verification key depending on the sender
        identity = signed_msg["identity"]
        signer_key = self.trusted_entities[identity]

        try:
            if msg["command"] in ["save_config", "restore_config", "factory_config"]:
                # Ignore signature check, the config commands don't need authentication! (Or do they?)
                pass
            elif not self.rsa_pkcs1_15_verify(
                signer_key.n, signer_key.e, json.dumps(msg).encode(), signature
            ):
                raise ValueError("invalid signature")

            response = self.exec_command(msg) #{"res": ok}
            signature = self.rsa_pkcs1_15_sign(self.skey, json.dumps(response).encode())

            return {"signed_res": response, "signature": signature.hex()}
        except ValueError as e:
            error_text = type(e).__name__ + ":" + str(e)
            signature = self.rsa_pkcs1_15_sign(self.skey, error_text.encode())
            print({"signed_error": error_text, "signature": signature.hex()})
            return {"signed_error": error_text, "signature": signature.hex()}


class Server(SmartCarpet):
    """Server allows access to the SmartCarpet functionalities via JSON messages.

    This is plumbing code, you can mostly ignore it in the scope of the lab.
    """

    rsa_pkcs1_15_sign = None
    rsa_pkcs1_15_verify = None

    def __init__(
        self,
        flag: str,
        key: RSA.RsaKey,
        cloud_key: RSA.RsaKey,
        config_key: bytes,
        in_file: BinaryIO = sys.stdin.buffer,
        out_file: BinaryIO = sys.stdout.buffer,
    ):
        """Initialize the Server object.

        Args:
            flag (str): the Oracle's secret flag
            key (RSA.RsaKey): the Carpet's secret key
            cloud_key (RSA.RsaKey): the Carpet Cloud's public key
            config_key (bytes): the Carpet's symmetric backup key
            in_file  (BinaryIO): io object for Oracle input
            out_file (BinaryIO): io object for Oracle output
        """
        self.in_file = in_file
        self.out_file = out_file

        super().__init__(key=key, cloud_key=cloud_key, config_key=config_key, flag=flag)

    def send_response(self, obj: dict):
        """Send a JSON-formatted response to the client.

        Args:
            obj (dict): the response object
        """
        res = json.dumps(obj) + "\n"
        self.out_file.write(res.encode())
        self.out_file.flush()

    def read_message(self):
        """Parse a JSON-formatted message from the client.

        Returns:
            dict: a dictionary representing the input JSON message.
        """
        msg = self.in_file.readline()
        return json.loads(msg)

    def main(self):
        while True:
            try:
                msg = self.read_message()
                res = self.exec_command_secure(msg)
                self.send_response(res)
            except (KeyError, ValueError, json.decoder.JSONDecodeError) as e:
                self.send_response(
                    {
                        "res": "Failed to execute command: "
                        + type(e).__name__
                        + ": "
                        + str(e)
                    }
                )
                break

        self.out_file.close()


if __name__ == "__main__":
    # This code allows you to run this server locally for testing.
    # Start the server and point your client to "localhost:PORT" to connect to it.
    # This can help you debug issues with your attack.

    from public import carpet_test_key, cloud_test_key
    from client import sign, verify

    import socketserver

    class LocalRequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            c = Server(
                "flag{exampleflag}",
                carpet_test_key,
                cloud_test_key,
                get_random_bytes(16),
                self.rfile,
                self.wfile,
            )
            c.rsa_pkcs1_15_sign = sign
            c.rsa_pkcs1_15_verify = verify
            c.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("localhost", PORT), LocalRequestHandler).serve_forever()
