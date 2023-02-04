#!/usr/bin/env python3
import json
import sys
from typing import BinaryIO

from Crypto.PublicKey import RSA
from Crypto.Random import random

PORT = 51040

"""
The SOC inside this Carpet might well be dusty, but your Carpet will not be!
"""


class SmartCarpet:
    def __init__(self, key: RSA.RsaKey, cloud_key: RSA.RsaKey, flag: str):
        self.skey = key
        self.flag = flag
        self.trusted_entities = {
            "carpet": self.skey,
            "carpet_cloud": cloud_key,
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
        signature:    RSA PKCS1-v1.5-style signature of the command
        The signature format is described in the client skeleton.

        Args:
            signed_msg (dict): the command to be handled

        Returns:
            dict: a dictionary representing JSON signed response.
        """
        print("exec_command_secure")
        msg = signed_msg["msg"]
        signature = bytes.fromhex(signed_msg["signature"])
        # Pick the verification key depending on the sender
        identity = signed_msg["identity"]
        signer_key = self.trusted_entities[identity]
        
        print("Signature: ", end="")
        print(signature)
        
        print("identity: ", end="")
        print(identity)
        
        print("signer_key: ", end="")
        print(signer_key)

        try:
            print("exec_command_secure, try")
            if not self.rsa_pkcs1_15_verify(
                signer_key.n, signer_key.e, json.dumps(msg).encode(), signature
            ):
                print("exec_command_secure, try, if not")
                raise ValueError("invalid signature")
            
            print("exec_command_secure, try, pass if not")
            response = self.exec_command(msg)
            print("exec_command_secure, try, exec_command")
            signature = self.rsa_pkcs1_15_sign(self.skey, json.dumps(response).encode())
            print("exec_command_secure, try, rsa_pkcs1_15_sign")
            return {"signed_res": response, "signature": signature.hex()}
        except ValueError as e:
            print("exec_command_secure, except")
            print(type(e).__name__ + ":" + str(e))
            error_text = type(e).__name__ + ":" + str(e)
            signature = self.rsa_pkcs1_15_sign(self.skey, error_text.encode())

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
        in_file: BinaryIO = sys.stdin.buffer,
        out_file: BinaryIO = sys.stdout.buffer,
    ):
        """Initialize the Server object.

        Args:
            flag (str): the Oracle's secret flag
            key (RSA.RsaKey): the Carpet's secret key
            cloud_key (RSA.RsaKey): the Carpet Cloud's public key
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
            print("*" * 42)
            try:
                print("main, try")
                msg = self.read_message()
                print("main, try, read_message")
                print("main, try, read_message -> msg: ", end="")
                print(msg)
                
                res = self.exec_command_secure(msg)
                print("main, try, exec_command_secure")
                print("main, try, exec_command_secure -> res: ", end="")
                print(res)
                
                self.send_response(res)
                print("main, try, send_response")
            except (KeyError, ValueError, json.decoder.JSONDecodeError) as e:
                print("main, except")
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
                self.rfile,
                self.wfile,
            )
            c.rsa_pkcs1_15_sign = sign
            c.rsa_pkcs1_15_verify = verify
            c.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("localhost", PORT), LocalRequestHandler).serve_forever()
