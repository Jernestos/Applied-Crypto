#!/usr/bin/env python3

import json
import sys
from typing import BinaryIO

from Crypto.PublicKey import ElGamal
from Crypto.Random import random

from public import ElGamalInterface

PORT = 51010

"""
No more untrusted, dusty carpets!
With this IoT Smart Carpet, you can constantly monitor
the level of dust in your carpet! Moreover, the communication
with your Smart Carpet is protected with Military Grade
Cryptography... You get a carpet you can trust!!!
"""


class SmartCarpet:
    def __init__(self, elgamal: ElGamalInterface, key: ElGamal.ElGamalKey, flag: str):
        self.key = key
        self.warranty_void = False
        self.flag = flag
        self.elgamal = elgamal

    def get_status(self) -> str:
        dust_lev = random.randint(1, 10000)
        msg = f"There's an awful lot of dust on your carpet: {dust_lev}kg"

        return msg

    def get_flag(self) -> str:
        return self.flag

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
        (c1, c2):  the ElGamal encryption of a json-formatted command
                   under the public key of the Carpet

        (p, g, y): the ElGamal public key to be used for
                   encrypting the responses.

        Args:
            msg (dict): the command to be handled

        Returns:
            dict: a dictionary representing JSON encrypted response.
        """

        enc_command_c1 = bytes.fromhex(msg["c1"])
        enc_command_c2 = bytes.fromhex(msg["c2"])

        to_key = None
        if "p" in msg and "g" in msg and "y" in msg:
            to_key = ElGamal.construct((msg["p"], msg["g"], msg["y"]))
        else:
            # default to carpet's key if no public key provided
            to_key = self.key

        try:
            # decrypt command and execute it
            command = self.elgamal.decrypt(
                self.key, enc_command_c1, enc_command_c2
            ).decode()
            res = self.exec_command(json.loads(command))

            # encrypt response
            c1, c2 = self.elgamal.encrypt(to_key, json.dumps(res).encode())
            return {"enc_res": {"c1": c1.hex(), "c2": c2.hex()}}
        except (ValueError, json.decoder.JSONDecodeError) as e:
            c1, c2 = self.elgamal.encrypt(
                to_key, json.dumps({"error": str(e)}).encode()
            )
            return {"enc_res": {"c1": c1.hex(), "c2": c2.hex()}}


class Server(SmartCarpet):
    """Server allows access to the SmartCarpet functionalities via JSON messages.

    This is plumbing code, you can mostly ignore it in the scope of the lab.
    """

    def __init__(
        self,
        flag: str,
        elgamal: ElGamalInterface,
        key: ElGamal.ElGamalKey,
        in_file: BinaryIO = sys.stdin.buffer,
        out_file: BinaryIO = sys.stdout.buffer,
    ):
        """Initialize the Server object.

        Args:
            flag (str): the Carpet's secret flag
            elgamal (ElGamalImpl): an elgamal implementation
            key (ElGamal.ElGamalKey): the Carpet's secret key
            in_file  (BinaryIO): io object for Oracle input
            out_file (BinaryIO): io object for Oracle output
        """
        self.in_file = in_file
        self.out_file = out_file

        super().__init__(elgamal, key=key, flag=flag)

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

    from public import carpet_test_key
    from client import ElGamalImpl

    import socketserver

    class LocalRequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            c = Server(
                "flag{exampleflag}",
                ElGamalImpl(),
                carpet_test_key,
                self.rfile,
                self.wfile,
            )
            c.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("localhost", PORT), LocalRequestHandler).serve_forever()
