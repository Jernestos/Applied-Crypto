#!/usr/bin/env python3
import json
import sys

from Crypto.Random import get_random_bytes
from Crypto.Random.random import choice
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Server():
    """ Server implements a simple secure server which takes commands from a client
    and executes them.

    The Server's main() function starts the server.
    """
    def __init__(self, flag, in_file=sys.stdin.buffer, out_file=sys.stdout.buffer):
        """ Initialize the Server object.

        This is plumbing code, you can safely ignore it in the scope of the lab.

        Args:
            flag (str): the Oracle's secret flag
            in_file  (io.TextIOBase): io object for Oracle input
            out_file (io.TextIOBase): io object for Oracle output
        """
        self.in_file = in_file
        self.out_file = out_file
        self.flag = flag

        self.block_size = 16
        self.k = get_random_bytes(self.block_size)

    def read_message(self):
        """ Parse a JSON-formatted message from the client using
        self.in_file.

        Returns:
            dict: a dictionary representing the input JSON message.
        """
        msg = self.in_file.readline()
        return json.loads(msg)

    def send_response(self, obj: str, encrypted : bool = True):
        """ Send a JSON-formatted response to the client using
        self.out_file. If encrypted is true, encrypt the response body.

        Args:
            obj (str): the response object
            encrypted (bool): control whether the response should be encrypted
        """
        if encrypted:
            cipher = AES.new(self.k, AES.MODE_CBC)
            ctxt = cipher.encrypt(pad(obj.encode(), self.block_size))
            encrypted_obj = cipher.iv + ctxt
            obj = encrypted_obj.hex()

        res = json.dumps({"res": obj}) + "\n"

        self.out_file.write(res.encode())
        self.out_file.flush()

    def read_command(self, msg: bytes, encrypted : bool = True) -> str:
        """ Parse a command from the input message.
        If encrypted is true, try to decrypt the command.

        Args:
            msg (dict): a dictionary, with a "command" key
            encrypted (bool): control whether the command should be decrypted

        Returns:
            str: the plaintext command.
        """
        command = msg["command"]

        if encrypted:
            encrypted_command = bytes.fromhex(msg["command"])
            iv = encrypted_command[:self.block_size]
            ctxt = encrypted_command[self.block_size:]

            cipher = AES.new(self.k, AES.MODE_CBC, iv = iv)
            command = unpad(cipher.decrypt(ctxt), self.block_size).decode()

        return command

    def exec_command(self, command: str):
        """ Implement handling of commands.

        Args:
            command (str): the command to be handled
        """
        if command == "hello":
            return "A very warm welcome to this server!   "\
                    "This command is not doing much, and your "\
                    "attack code is not expected to reach it."
        else:
            raise ValueError("The command you tried to execute "\
                    "was not recognized. Nevertheless, we think you "\
                    "deserve a flag for having made it this far: " + self.flag +"\n"\
                    "Can you decrypt it?")

    def main(self):
        """ Execute the server's main loop: wait for commands from the client
        and try to execute them, then send eventual responses or error messages
        back to the client.
        """
        while True:
            try:
                msg = self.read_message()
                command = self.read_command(msg)
                res = self.exec_command(command)
                self.send_response(res)
            except (KeyError,ValueError,json.decoder.JSONDecodeError) as e:
                print("Failed to execute command: " + type(e).__name__ + ": " + str(e))
                self.send_response("Failed to execute command: " + type(e).__name__ + ": " + str(e))

if __name__ == "__main__":
    # This code allows you to run this server locally for testing.
    # Start the server and point your client to "localhost:50404" to connect to it.
    # This can help you debug issues with your attack.

    import os
    if "AC" in os.environ:
        import secret
        Server(secret.flag).main()
        sys.exit()

    import socketserver
    class LocalRequestHandler(socketserver.StreamRequestHandler):
        def handle(self):
            c = Server("flag{exampleflag}", self.rfile, self.wfile)
            c.main()

    class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    TCPServer(("localhost", 50404), LocalRequestHandler).serve_forever()
