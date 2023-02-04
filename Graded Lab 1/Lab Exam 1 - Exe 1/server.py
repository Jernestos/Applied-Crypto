#!/usr/bin/env python3
import io
import json
import sys

from Crypto.Random import get_random_bytes
from Crypto.Random.random import choice
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class Oracle():
    """ Oracle implements an IND-CPA challenger.

    The challenger interacts with an adversary, and reveals a flag to the
    adversary if they show a significant advantage in the IND-CPA game.

    The Oracle's main() function starts the challenger.
    """

    def __init__(self, flag: str,
            in_file: io.TextIOBase =sys.stdin.buffer,
            out_file: io.TextIOBase =sys.stdout.buffer):
        """ Initialize the Oracle object.

        This is plumbing code, you can safely ignore it in the scope of the lab.

        Args:
            flag (str): the Oracle's secret flag
            in_file  (io.TextIOBase): io object for Oracle input
            out_file (io.TextIOBase): io object for Oracle output
        """
        self.in_file = in_file
        self.out_file = out_file
        self.flag = flag
        self.rounds = 1000

    def read_message(self) -> dict:
        """ Parse a JSON-formatted message from the adversary using self.in_file.

        Returns:
            dict: a dictionary representing the input JSON message.
        """
        msg = self.in_file.readline()
        return json.loads(msg)

    def send_response(self, obj: str):
        """ Send a JSON-formatted response to the adversary using self.out_file.

        Args:
            obj (str): the response object
        """
        res = json.dumps({"res": obj}) + "\n"
        self.out_file.write(res.encode())
        self.out_file.flush()

    def left_or_right(self, k: bytes, b: int, m0: bytes, m1: bytes):
        """ Left or Right functionality of the oracle:
        based on bit b, send either cbc_encrypt(m0) or cbc_encrypt(m1) to the adversary.

        Args:
            k (bytes): AES-128-CBC key
            b (int): either 0 or 1
            m0 (bytes): message 0 (or left)
            m1 (bytes): message 1 (or right)
        """

        def cbc_encrypt(cipher, msg: bytes) -> bytes:
            padded_msg = pad(msg, AES.block_size)
            ctxt = cipher.encrypt(padded_msg)
            return cipher.iv + ctxt

        cipher = AES.new(k, AES.MODE_CBC)

        if b == 0:
            self.send_response(cbc_encrypt(cipher, m0).hex())
        if b == 1:
            self.send_response(cbc_encrypt(cipher, m1).hex())

    def cpa_game(self):
        """ Single IND-CPA game round:
        sample a bit b at random and read messages from the adversary.

        If a message's 'command' key contains the 'oracle' value, read the m0 and m1 keys (strings),
        and call left_or_right with these values.

        If a message's 'command' key contains the 'guess' value, read the 'guess' key (int),
        compare it to the sampled bit b, and terminate the game.

        Returns:
            bool: true if the adversary correctly guessed b
        """

        # Select the bit b at random
        b  = choice([0, 1])

        # Generate a random 128-bit AES encryption key k
        k = get_random_bytes(16)

        bguess = None

        while True:
            try:
                msg = self.read_message()
                cmd = msg["command"]
                if cmd == "oracle":
                    self.left_or_right(
                            k,
                            b,
                            msg["m0"].encode("utf-8"),
                            msg["m1"].encode("utf-8"))
                elif cmd == "guess":
                    bguess = msg["guess"]
                    break
                else:
                    raise ValueError("No such command: " + cmd)

            except (KeyError,ValueError,json.decoder.JSONDecodeError) as e:
                self.send_response("Failed to parse input: " + type(e).__name__ + ": " + str(e))

        # Check if the client has won the game
        if b == bguess:
            return True

        return False

    def main(self):
        """ Execute the oracle's main loop: play the IND-CPA game, and send a
        flag to the adversary if they won self.rounds consecutive games.
        """
        for i in range(self.rounds):
            if not self.cpa_game():
                self.send_response("You lost")
                break
            self.send_response(f"You won round {i+1}/{self.rounds}")
        else:
            self.send_response(self.flag)
        self.out_file.close()

if __name__ == "__main__":
    # This code allows you to run this server locally for testing.
    # Start the server and point your client to "localhost:50400" to connect to it.
    # This can help you debug issues with your attack.
    # i.e., just run "python server.py" to start the server locally

    import os
    if "AC" in os.environ:
        import secret
        Oracle(secret.flag).main()
        sys.exit()

    import socketserver
    class LocalRequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            c = Oracle("flag{exampleflag}", self.rfile, self.wfile)
            c.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("localhost", 50400), LocalRequestHandler).serve_forever()
