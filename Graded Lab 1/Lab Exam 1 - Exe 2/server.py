#!/usr/bin/env python3
import io
import json
import sys

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#Hello TA, I also supplied this file as it is part of the task to understand the code. The writeup is in the file "client.py"

class Server():
    """ Server implements a padding-error guessing challenger.

    The challenger interacts with an adversary, and reveals a flag to the
    adversary if they show a significant advantage in the padding-error guessing game.

    The Server's main() function starts the challenger.
    """

    def __init__(self, flag: str,
            in_file: io.TextIOBase =sys.stdin.buffer,
            out_file: io.TextIOBase =sys.stdout.buffer):
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
        self.rounds = 3000

        self.block_size = 16
        self.k = get_random_bytes(self.block_size)
        self.ctxt_db = {}

    def read_message(self):
        """ Parse a JSON-formatted message from the adversary using
        self.in_file.

        Returns:
            dict: a dictionary representing the input JSON message.
        """
        msg = self.in_file.readline()
        return json.loads(msg)

    def send_response(self, obj: str, encrypted : bool = True):
        """ Send a JSON-formatted response to the adversary using
        self.out_file. If encrypted is true, encrypt the response body.

        Args:
            obj (str): the response object
            encrypted (bool): control whether the response should be encrypted
        """
        if encrypted:
            cipher = AES.new(self.k, AES.MODE_CBC) #create new cipher under CBC mode
            ctxt = cipher.encrypt(pad(obj.encode(), self.block_size)) #obj is a string, if no error, it's the string to encrypt; that's were we distinguish between our message and the error message; no exception here
            encrypted_obj = cipher.iv + ctxt
            self.ctxt_check(encrypted_obj, False) #value error
            obj = encrypted_obj.hex() #convert bytes to hex

        res = json.dumps({"res": obj}) + "\n"
        self.out_file.write(res.encode())
        self.out_file.flush()

    def read_command(self, msg: dict, encrypted : bool = True) -> str:
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
            encrypted_command = bytes.fromhex(msg["command"]) #if we use a non-hex number e.g. f35, then we get a value error here
            self.ctxt_check(encrypted_command) #throws value error if ciphertext already seen
            iv = encrypted_command[:self.block_size]
            ctxt = encrypted_command[self.block_size:]

            cipher = AES.new(self.k, AES.MODE_CBC, iv = iv) #new cipher
            
            #this is the critial part. so we will query using a valid hex message never seen before for each iteration
            command = unpad(cipher.decrypt(ctxt), self.block_size).decode() #cipher.decrypt returns bytes, unpad returns bytes,decode makes bytes -> ascii; here: either unpad error (wrong padding), or cannot be decoded to utf exception
            #string keyed under "command" will de decrypted using the server key. If exception, then exception will be 
        return command

    def ctxt_check(self, ctxt: bytes, check: bool = True):
        """ Prevent trivial wins by reflecting the responses as commands, or by
        sending the same ciphertext multiple times.

        Store every block of the input ciphertext.  If check is true, and a
        block of ciphertext was already seen, raise an exception.

        Args:
            ctxt (bytes): the ciphertext
            check (bool): raise an exception in case of duplicate blocks
        """
        ctxt_blocks = [ctxt[i:i+self.block_size] for i in range(0, len(ctxt), self.block_size)]
        if check and any(self.ctxt_db.get(ctxt_block) for ctxt_block in ctxt_blocks): #check for all blocks of the ciphertext if is already seen
            raise ValueError("You cannot just reflect or repeat ct blocks.")

        for ctxt_block in ctxt_blocks:
            self.ctxt_db[ctxt_block] = True #add the blocks of the new ciphertext to the dictionary


    def exec_command(self, command: str):
        """ Implement handling of dummy commands.

        Args:
            command (str): the command to be handled
        """
        if command == "hello":
            return "A very warm welcome to the challenge! "\
                    "This command is not doing much, and your "\
                    "attack code is not expected to reach it."

        raise ValueError("The command you tried to execute "\
                "was not recognized: " + command)

    def guess_loop(self):
        """ Single paddig-guessing game round: read messages from the
        adversary.

        If a message does not contain a 'guess' key, try to decrypt the value
        for the 'command' key, and execute the corresponding command.

        If the message contains a 'guess' key, read the corresponding value
        (bool) and terminate the game.

        Returns:
            bool: true if the adversary correctly guessed whether a padding
                  error occurred.
        """
        padding_error = None
        msg = None

        while True:
            try:
                msg = self.read_message() #get dictionary of json , JSONDecodeError  (e.g missing :)
                if "guess" in msg.keys():
                    # stop the loop and check the guess
                    break
                #if there is no error, we decrypted something to plaintext sucessfully.
                command = self.read_command(msg) #EXCEPTION COULD HAPPEN HERE, value error, padding error, utf error
                
                #we are not supposed to land here
                padding_error = False
                res = self.exec_command(command) #EXCEPTION COULD HAPPEN HERE, value error
                self.send_response(res) #EXCEPTION COULD HAPPEN HERE
            except (KeyError,ValueError,json.decoder.JSONDecodeError) as e:
                #json error will  set padding_error here to false
                #value error will  set padding_error here to false
                #because of "command" in str(e)
                padding_error = None
                
                # Something went wrong, send an encrypted error message to the client
#                print("Failed to execute command: " + type(e).__name__ + ": " + str(e))
                self.send_response("Failed to execute command: " + type(e).__name__ + ": " + str(e))
                # If there is a padding error, record it for the guess check
                if "padding" in str(e) or "Padding" in str(e):
                    padding_error = True
                if "utf" in str(e) or "command" in str(e):
                    padding_error = False

        padding_error_guess = msg["guess"]

        if padding_error == padding_error_guess and padding_error_guess is not None:
            return True

        return False

    def main(self):
        """ Execute the server's main loop: play the padding-guessing game, and
        send a flag to the adversary if they won self.rounds consecutive games.
        """
        for i in range(self.rounds):
            if not self.guess_loop():
                self.send_response("You lost", encrypted = False) #try the games 3000 times
                break
            self.send_response(f"You won round {i+1}/{self.rounds}", encrypted = False)
        else:
            self.send_response(self.flag, encrypted = False)

        self.out_file.close()

if __name__ == "__main__":
    # This code allows you to run this server locally for testing.
    # Start the server and point your client to "localhost:50401" to connect to it.
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

    TCPServer(("localhost", 50401), LocalRequestHandler).serve_forever()
