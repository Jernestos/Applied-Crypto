#!/usr/bin/env python3
import json
import sys
import time
from typing import BinaryIO

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Random import random

PORT = 51030

"""
Yet another Carpet.
"""


class SmartCarpet:
    def __init__(self, key: ECC.EccKey, cloud_key: ECC.EccKey, flag: str):
        self.key = key
        self.flag = flag
        self.trusted_entities = {
            "carpet": self.key, #carpet key
            "carpet_cloud": cloud_key, # test key
        }

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
                    "error": "The command you tried to execute "
                    "was not recognized: " + command
                }

    def exec_command_secure(self, signed_msg: dict) -> dict:
        """Wraps exec_command with a layer of signature.

        Takes as input a json dictionary, containing:
        msg:          a dictionary representing command
        id:           the identity of the signer
        signature:    the ECDSA signature of the command

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

        h = SHA256.new(json.dumps(msg).encode())
        verifier = DSS.new(signer_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)

            response = self.exec_command(msg)
            res_hash = SHA256.new(json.dumps(response).encode())
            signature = DSS.new(self.key, 'fips-186-3').sign(res_hash)
            return {"signed_res": response, "signature": signature.hex()}
        except ValueError as e:
            error_text = time.ctime() + ": error: " + type(e).__name__ + ": " + str(e)
            err_hash = SHA256.new(error_text.encode())
            signature = DSS.new(self.key, 'fips-186-3').sign(err_hash)
            return {"signed_error": error_text, "signature": signature.hex()}


class Server(SmartCarpet):
    """Server allows access to the SmartCarpet functionalities via JSON messages.

    This is plumbing code, you can mostly ignore it in the scope of the lab.
    """

    def __init__(
        self,
        flag: str,
        key: ECC.EccKey,
        cloud_key: ECC.EccKey,
        in_file: BinaryIO = sys.stdin.buffer,
        out_file: BinaryIO = sys.stdout.buffer,
    ):
        """Initialize the Server object.

        Args:
            flag (str): the Carpet's secret flag
            key (EccKey): the Carpet's secret key
            cloud_key (EccKey): the Carpet Cloud's public key
            in_file  (BinaryIO): io object for Oracle input
            out_file (BinaryIO): io object for Oracle output
        """
        self.in_file = in_file
        self.out_file = out_file

        super().__init__(key=key, cloud_key=cloud_key, flag=flag)

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

    import socketserver

    class LocalRequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            c = Server(
                "flag{exampleflag}",
                carpet_test_key,
                cloud_test_key,
                self.rfile,
                self.wfile,
            )
            c.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("localhost", PORT), LocalRequestHandler).serve_forever()
