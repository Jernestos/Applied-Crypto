#!/usr/bin/env python3
import json
import sys

from typing import Optional, BinaryIO

from Crypto.Random import random
from Crypto.PublicKey.ECC import EccKey
from Crypto.PublicKey import ECC

from public import ECCInterface

PORT = 51020

"""
The QA team told us that some customers were unhappy with the fact that our Smart Carpet
could not handle long messages. We thought about it quite a bit (we even learned what a
KEM is!) and we've decided to settle for a static ECDH key exchange, followed by
AES-GCM as AEAD.

Any user can provide their public key to the carpet to perform the key agreement. Then,
it's just a matter of sending encrypted messages back and forth.

The Smart Carpet has never been this fast! Looking forward to when the folks
at /r/wallstreetbets are going to buy our stocks!
"""

CURVE = "NIST P-256"


class SmartCarpet:
    def __init__(self, key: EccKey, ecc: ECCInterface, flag: str):
        self.key = key
        self.flag = flag
        self.user_key: Optional[EccKey] = None
        self.ecc = ecc
        self.key_enc, self.key_dec = b"", b""

    def get_status(self) -> str:
        dust_lev = random.randint(1, 10000)
        msg = f"There's an awful lot of dust on your carpet: {dust_lev}kg"

        return msg

    def get_flag(self) -> str:
        return self.flag

    def set_user_key(self, payload: dict) -> dict:
        print("set_user_key")
        user_x = int(payload["x"], 16)
        user_y = int(payload["y"], 16)

        self.user_key = ECC.construct(curve=CURVE, point_x=user_x, point_y=user_y)
        print("set_user_key, ECC.construct")
        self.key_enc, self.key_dec = self.ecc.derive_symmetric_keys(
            self.key, self.user_key
        )
        print("set_user_key, derive_symmetric_keys")
        return {"res": "User key set"}

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
            case "backdoor":
                return {"res": self.get_flag()}
            case _:
                return {
                    "res": "The command you tried to execute "
                    "was not recognized: " + command
                }

    def exec_command_secure(self, msg: dict) -> dict:
        """Wraps exec_command with a layer of encryption.

        Takes as input a json dictionary, containing:
        (nonce, ciphertext, tag): The necessary components for AES-GCM decryption

        Args:
            msg (dict): the command to be handled

        Returns:
            dict: a dictionary representing JSON encrypted response.
        """
        print("exec_command_secure")
        print("exec_command_secure, msg: ", end="")
        print(msg)
        ciphertext = bytes.fromhex(msg["ciphertext"])
        tag = bytes.fromhex(msg["tag"])
        nonce = bytes.fromhex(msg["nonce"])

        if not self.user_key:
            return {"res": "You must set a user key first"}

        try:
            # decrypt command and execute it
            print("exec_command_secure, try")
            command = self.ecc.decrypt(self.key_dec, ciphertext, tag, nonce).decode()
            print("exec_command_secure, command")
            res = self.exec_command(json.loads(command))

            # encrypt response
            ctxt, tag, nonce = self.ecc.encrypt(self.key_enc, json.dumps(res).encode())

            return {
                "enc_res": {
                    "ciphertext": ctxt.hex(),
                    "tag": tag.hex(),
                    "nonce": nonce.hex(),
                }
            }
        except RuntimeError as e:
            ctxt, tag, nonce = self.ecc.encrypt(
                self.key_enc, json.dumps({"error": str(e)}).encode()
            )

            return {
                "enc_res": {
                    "ciphertext": ctxt.hex(),
                    "tag": tag.hex(),
                    "nonce": nonce.hex(),
                }
            }


class Server(SmartCarpet):
    """Server allows access to the SmartCarpet functionalities via JSON messages.

    This is plumbing code, you can mostly ignore it in the scope of the lab.
    """

    def __init__(
        self,
        flag: str,
        key: EccKey,
        ecc: ECCInterface,
        in_file: BinaryIO = sys.stdin.buffer,
        out_file: BinaryIO = sys.stdout.buffer,
    ):
        """Initialize the Server object.

        Args:
            flag (str): the Carpet's secret flag
            key (EccKey): the Carpet's secret key
            ecc (ECCInterface): ECC implementation
            in_file  (io.TextIOBase): io object for Oracle input
            out_file (io.TextIOBase): io object for Oracle output
        """
        self.in_file = in_file
        self.out_file = out_file

        super().__init__(key=key, flag=flag, ecc=ecc)

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
            print("*" * 40)
            print("*" * 40)
            print("main")
            try:
                print("main, try")
                msg = self.read_message()
                print("main, try, read_message")
                if "command" in msg and msg["command"] == "set_user_key":
                    print("main, try, if")
                    res = self.set_user_key(msg)
                    print("main, try, if-end")
                else:
                    print("main, try, else")
                    res = self.exec_command_secure(msg)
                    print("main, try, else-end")
                print("main, try, res")
                print(res)
                self.send_response(res)
            except (KeyError, ValueError, json.decoder.JSONDecodeError) as e:
                print("main, except")
                print("res: " + "Failed to execute command: " + type(e).__name__ + ": " + str(e))
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

    from public import carpet_test_privkey
    from client import ECCImpl

    import socketserver

    class LocalRequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            c = Server(
                "flag{exampleflag}",
                carpet_test_privkey,
                ECCImpl(),
                self.rfile,
                self.wfile,
            )
            c.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("localhost", PORT), LocalRequestHandler).serve_forever()
