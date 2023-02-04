from telnetlib import Telnet
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

#Hello TA, I also supplied this file tht contains writeup further down.

def json_recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return json.loads(line.decode("utf-8"))

def json_send(tn: Telnet, req: dict):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")

#relict of previous task
def send_oracle_command(tn: Telnet, m0: str, m1: str) -> str:
    """Sends the challenge messages to the IND-CPA oracle

    Args:
        tn (Telnet): a telnet client
        m0 (str): first message to encrypt
        m1 (str): second message to encrypt

    Returns:
        str: the response of the server
    """
    json_send(tn, {"command": "oracle", "m0": m0, "m1": m1})
    return json_recv(tn)["res"]

def send_guess(tn: Telnet, guess: bool) -> str:
    json_send(tn, {"guess": guess})
    return json_recv(tn)["res"]
    
    
def send_my_enc_stuff(tn: Telnet, value_to_send) -> str:
    json_send(tn, {"command": value_to_send})
    return json_recv(tn)["res"]

def attack(tn: Telnet):
    """
    Strategy:
        By inspection of the source code of the server (see server.py, my comments), line "command = unpad(cipher.decrypt(ctxt), self.block_size).decode()" of read_command(...), called in "command = self.read_command(msg)" of method guess_loop(self) is where our padding and decoding errors can happen. After this command, it states that we are not supposed to reach it, so we can ignore the last 3 codelines of the try body.
            In the method guess_loop, in the except branch, this is where the exception messages are created. Notice that the lenghts of these messages are not of the same length.
            E.g. When we have a exception triggered by a decode-error then we get a message like: 
               Failed to execute command: "UnicodeDecodeError: 'utf-8' codec can't decode byte 0x9e in position 0: invalid start byte"
                This string is of length 90
                When we get a padding error, then we get an exception like this: "Failed to execute command: ValueError: PKCS#7 padding is incorrect."
                This string is of length 67
                We also get padding errors like: "ValueError: Padding is incorrect."
                This string is of length 33
            Since each character is 1 byte, and 67 - 33 > 16 bytes, and 90 - 67 > 16 bytes, this means that we can infer if it was a decoding error or not, based on the length of the encrypted error message - the encrypted error message with the biggest size would correspond to the decoding error; the other 2 lengths correspond to an issue with the padding. Note that the difference in length, which is greater than 16 bytes, gets translated as at least 1 additional 16 byte block -> the longer the message, the more 16 blocks it is.
            
            Note that this analysis still hold when we consider the hex-value of the encrypted error message.
            
            procedure:
                
            So knowing the above, we can first try to figure out the lengths of the encrypted error messages when interacting with the server, which on my system, are {160, 288, 192}. Therefore a 288 hex digits correspond to the decoding error, the other two correspond to the padding error. To make this indepedent of the system, first send a few messages to the server, under consideration of (1).
            
            (1)
            To prevent sending the same ciphertext, we generate randomly two ciphertextblocks, each of 16 bytes, and concatenate them. We need (at least) two because the first one acts as the IV, the second one as the encrypted plaintext. So with negligible probability, we send a block already twice.
            
            So if we get back an error message of 288 (or just the biggest in the set/list) hex digits, then we guess accordingly, that is guess that it's not a padding error (b = False).
            In the other case, we guess b = True, that is it's a padding error.
            
            We put this into a loop, and iterate 3000 times, and get the flag.
                
    """
    
    error_messages_length_set = set({})
    #we know we can trigger 3 error messages as described above
    #so we want to receive these 3 encrypted error messages to determine their lenghts.
    while len(error_messages_length_set) < 3:
        randomstuff1 = get_random_bytes(AES.block_size)
        randomstuff2 = get_random_bytes(AES.block_size)
        ctxt = randomstuff1 + randomstuff2
        res = send_my_enc_stuff(tn, bytes.hex(ctxt))
        error_messages_length_set.add(len(res))
    
    #convert the set into a list, sort asc. the list; the last entry has the biggest entry of the list and represents encrypted error messages for UTF-8 decoding errors
    biggest_length = sorted(error_messages_length_set)[len(error_messages_length_set) - 1]
    
    #now we play the guessing game
    for _ in range(3000):
        randomstuff1 = get_random_bytes(AES.block_size)
        randomstuff2 = get_random_bytes(AES.block_size)
        ctxt = randomstuff1 + randomstuff2

        res = send_my_enc_stuff(tn, bytes.hex(ctxt))
        if len(res) == biggest_length:
            b = False #UTF-8 decoding error
        else:
            b = True #invalid padding -> padding error
        res = send_guess(tn, b) #guess accordingly
        if "lost" in res:
            print("Lost")
            break
        else:
            print(res)
    print(json_recv(tn))

if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50401

    #localhost:50400
#    HOSTNAME = "localhost"
#    PORT = 50401
    
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
