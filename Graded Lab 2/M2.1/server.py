#!/usr/bin/env python3
import json
import sys
from os import path
from typing import Optional, Union, BinaryIO

from Crypto.Random import random
from Crypto.PublicKey.ECC import EccKey
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256

from public import ECCInterface

PORT = 51021

"""
Well... now the hardware team is nagging us again! Something about randomness being hard
to generate on a smart carpet or something like that...
Anyway, I *think* I've fixed it, but if you need help you can contact our customer service.
Just send your flag to us and we'll get back to you in a few days!
"""

CURVE = "NIST P-256"


class NonceGenerationError(Exception):
    pass


class SmartCarpet:
    def __init__(
        self, key: EccKey, ecc: ECCInterface, customer_service_key: EccKey, flag: str
    ):
        self.key = key
        self.customer_service_key = customer_service_key
        self.user_key: Optional[EccKey] = None
        self.ecc = ecc

        self.report_sent = False
        self.flag = flag
        curr_path = path.abspath(path.dirname(__file__))
        self.pi_file = open(path.join(curr_path, "pi_digits.txt"), "rb")

        self.enc_key_cs, _ = self.ecc.derive_symmetric_keys(
            self.key, self.customer_service_key
        )
        self.enc_key, self.dec_key = b"", b""

    def get_status(self) -> str:
        dust_lev = random.randint(1, 10000)
        msg = f"There's an awful lot of dust on your carpet: {dust_lev}kg"

        return msg

    def send_status_to_customer_service(self) -> Union[str, dict[str, str]]:
        """ Creates an encrypted payload to be sent to the customer service

        This method logs the dust level and sends it to the customer service, encrypted with the encryption key derived from the carpet's private key
        and the customer service's public key.
        """
        dust_lev = random.randint(1, 10000)
        msg = f"[Smart Carpet Dust Logging] User #1337 has sent a dust report to the customer service. Current dust level: {dust_lev}kg"

        try:
            nonce = self.extract_nonce_from_secure_randomness()
        except NonceGenerationError as e:
            return str(e)

        ctxt, tag, _ = self.ecc.encrypt(self.enc_key_cs, msg.encode(), nonce=nonce)

        return {"ciphertext": ctxt.hex(), "tag": tag.hex(), "nonce": nonce.hex()}

    def get_flag(self) -> str:
        return self.flag

    def send_flag_to_customer_service(self) -> Union[str, dict[str, str]]:
        """Prepares an encrypted ticket to be sent to the customer service

        This method takes the flag and sends it to the customer service, encrypted with the encryption key derived from the carpet's private key
        and the customer service's public key. This method may only be called once: you definitely don't want to send the same thing to the
        customer service, right?
        """
        print("send_flag_to_customer_service START")
        if self.report_sent:
            print("send_flag_to_customer_service IF clause")
            raise Exception("Flag already sent!")
        else:
            print("send_flag_to_customer_service ELSE clause")
            try:
                print("send_flag_to_customer_service ELSE clause - try - extract_nonce_from_secure_randomness START")
                nonce = self.extract_nonce_from_secure_randomness()
                print("send_flag_to_customer_service ELSE clause - try - extract_nonce_from_secure_randomness END")
            except NonceGenerationError as e:
                print("send_flag_to_customer_service ELSE clause - except clause - NonceGenerationError")
                return str(e)
            
            print("send_flag_to_customer_service ELSE clause - got the flag")
            self.report_sent = True

            ctxt, tag, _ = self.ecc.encrypt(
                self.enc_key_cs, self.get_flag().encode(), nonce=nonce
            )

            return {"ciphertext": ctxt.hex(), "tag": tag.hex(), "nonce": nonce.hex()}

    def extract_nonce_from_secure_randomness(self) -> bytes:
        """Extracts a nonce from randomness, to be used for AES-GCM

        Our friends at Crown Sterling wrote this about their RNG:

        'CrownRNG exploits the by-default randomness of irrational numbers. Mathematically speaking, irrational
        numbers are defined as numbers that can't be expressed in terms of ratios of two integers. They are proven
        to have digital sequences, also known as mantissas, extending to infinity without ever repeating. Therefore,
        they are excellent sources for true randomness [...]'
        """

        ENTROPY_DIGITS = 2
        NONCE_SIZE = 16

        offset = random.randint(1, 100)
        self.pi_file.seek(offset, 1)

        entropy = self.pi_file.read(ENTROPY_DIGITS)
        #print("offset: ", end="")
        #print(offset)
        
        #print("entropy: ", end="")
        #print(entropy)
        # This happens if we're at the end of the file
        # ...wow! you sure use a lot of entropy!
        if len(entropy) < ENTROPY_DIGITS:
            raise NonceGenerationError("Out of entropy!")

        h = SHA256.new()
        h.update(entropy)
        nonce = h.digest()[:NONCE_SIZE]
        #print("nonce: ", end="")
        #print(nonce.hex())
        return nonce

    def set_user_key(self, payload: dict) -> dict:
        print("set_user_key - START")
        user_x = int(payload["x"], 16)
        user_y = int(payload["y"], 16)

        self.user_key = ECC.construct(curve=CURVE, point_x=user_x, point_y=user_y)
        
        print("set_user_key, derive_symmetric_keys - START")
        self.enc_key, self.dec_key = self.ecc.derive_symmetric_keys(
            self.key, self.user_key
        )
        print("set_user_key, derive_symmetric_keys - END")
        print("set_user_key - END")
        return {"res": "User key set"}


    def exec_command(self, msg: dict) -> dict:
        """Handles commands.

        Args:
            msg (dict): the command to be handled

        Returns:
            dict: a dictionary representing JSON response.
        """

        command = msg["command"]
        print("exec_command")
        match command:
            case "get_status":
                return {"status": self.get_status()}
            case "send_status_to_customer_service":
                print("exec_command - case send_status_to_customer_service")
                return {
                    "msg": "Please send this status to the customer service",
                    "res": self.send_status_to_customer_service(),
                }
            case "send_flag_to_customer_service":
                try:
                    print("exec_command - case send_flag_to_customer_service - try clause")
                    res = self.send_flag_to_customer_service()
                    print("RESULT OF: exec_command - case send_flag_to_customer_service - try clause: ", end="")
                    print({
                                            "msg": "Please send this flag to the customer service",
                                            "res": res,
                                        })
                    return {
                        "msg": "Please send this flag to the customer service",
                        "res": res,
                    }
                except Exception as e:
                    print("exec_command - case send_flag_to_customer_service - except clause")
                    print("Exception: ", end="")
                    print(str(e))
                    return {"msg": str(e)}
            case _:
                print("exec_command - case default - except clause")
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
        
        print("exec_command_secure, START")
        ciphertext = bytes.fromhex(msg["ciphertext"])
        tag = bytes.fromhex(msg["tag"])
        nonce = bytes.fromhex(msg["nonce"])

        if not self.user_key:
            return {"res": "You must set a user key first"}

        try:
            # Generate a nonce to encrypt the server response
            print("exec_command_secure, try, extract_nonce_from_secure_randomness - START")
            nonce_enc = self.extract_nonce_from_secure_randomness()
            print("exec_command_secure, try, extract_nonce_from_secure_randomness - END")
        except NonceGenerationError as e:
            print("exec_command_secure, 1st except")
            print("Exception: ", end="")
            print(str(e))
            return {"res": str(e)}

        try:
            print("exec_command_secure, 2nd try")
            # decrypt command and execute it
            command = self.ecc.decrypt(self.dec_key, ciphertext, tag, nonce).decode()
            print("command: ", end="")
            print(command)
            print("exec_command_secure, 2nd try, decrypt and decode")
            
            print("exec_command_secure, 2nd try, exec_command - START")
            res = self.exec_command(json.loads(command))
            print("exec_command_secure, 2nd try, exec_command - END")
            
            # encrypt response
            ctxt, tag, nonce = self.ecc.encrypt(
                self.enc_key, json.dumps(res).encode(), nonce=nonce_enc
            )
            #print("ctxt: ", end="")
            #print(ctxt.hex())
            #print("tag: ", end="")
            #print(tag.hex())
            #print("nonce: ", end="")
            #print(nonce.hex())
            #print("exec_command_secure, 2nd try, encrypt")
            
            print("RETURN VALUE OF exec_command_secure: ", end="")
            print({
                            "enc_res": {
                                "ciphertext": ctxt.hex(),
                                "tag": tag.hex(),
                                "nonce": nonce.hex(),
                            }
                        })
            
            return {
                "enc_res": {
                    "ciphertext": ctxt.hex(),
                    "tag": tag.hex(),
                    "nonce": nonce.hex(),
                }
            }
        except RuntimeError as e:
            print("exec_command_secure, 2nd except")
            print("Exception: ", end="")
            print(str(e))
            ctxt, tag, nonce = self.ecc.encrypt(
                self.enc_key, json.dumps({"error": str(e)}).encode(), nonce=nonce_enc
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
        ecc: ECCInterface,
        key: EccKey,
        customer_service_key: EccKey,
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

        super().__init__(
            key=key, flag=flag, ecc=ecc, customer_service_key=customer_service_key
        )

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
                print("main, try, read_message: ", end="")
                print(msg)
                if "command" in msg and msg["command"] == "set_user_key":
                    print("main, try, if-case: set_user_key-START")
                    res = self.set_user_key(msg)
                    print("main, try, if-case: set_user_key-END")
                else:
                    print("main, try, else-case: exec_command_secure-START")
                    res = self.exec_command_secure(msg)
                    print("res: ", end="")
                    print(res)
                    print("main, try, else-case: exec_command_secure-END")
                
                print("RESPONSE TO SEND: ", end="")
                print(res)
                self.send_response(res)
                print("main, try, send_response")
            except (KeyError, ValueError, json.decoder.JSONDecodeError) as e:
                print("main, except")
                print("exception: ", end="")
                print("Failed to execute command: " + type(e).__name__ + ": "+ str(e))
                
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

    from public import customer_service_pubkey, carpet_test_privkey
    from client import ECCImpl

    import socketserver

    class LocalRequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            c = Server(
                "flag{exampleflag}",
                ECCImpl(),
                carpet_test_privkey,
                customer_service_pubkey,
                self.rfile,
                self.wfile,
            )
            c.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("localhost", PORT), LocalRequestHandler).serve_forever()
