from telnetlib import Telnet
import json

def json_recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return json.loads(line.decode("utf-8"))

def json_send(tn: Telnet, req: dict):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")

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

def send_guess(tn: Telnet, guess: int) -> str:
    """Sends a guess to the oracle

    Args:
        tn (Telnet): a telnet client
        guess (int): 0/1 the guess of which message the oracle encrypted in the response

    Returns:
        str: the response of the oracle
    """
    json_send(tn, {"command": "guess", "guess": guess})
    return json_recv(tn)["res"]

def attack(tn: Telnet):
    """
    Strategy: Observe that in the server code, the IND-CPA game is not fully correctly implemented - is does not check if within a query (msg0, msg1), the length of these two messages are of equal length. This is what we can exploit to get the flag. So we define msg0 as a 16 byte block, and msg1 as 2 blocks (32 bytes), each 16 byte block. Note that msg0 is shorter than msg1 (by 16 bytes resp. one 16 byte block) By the API docs, the IV, if not specified for CBC_MODE, is randomly chosen, and in the server implementation, is chosen randomly and new each for each query. Since the two aforementioned messages are a multiple of the blocklength (AES.block_length returns 16, as in 16 bytes = 128 bit AES [which matches the description of the challange]), these two messages will be padded with another additional block, full of bytes of value 16. What still holds that the resulting ciphertext of the padded msg0 is still shorter (by a block_length = 16 bytes) than the resulting ciphertext of the padded msg1. Using this, we can distinguish if the server chose b = 0 or b = 1. If b = 0, then msg0 will be encrypted and we check if the ciphertext has a length <= _SIZE_. If b = 0, then that's always true, so we guess 0. Otherwise, if b = 1, then msg1 is encrypted and the size of the ciphertext has a length > _SIZE_. If b = 1, then this always true, so we guess 1.
        _SIZE_ = 96: Consider if msg0 is chosen. first it will be padded before it's encrypted , resulting in 3 blocks (one iv block), each 16-byte. Now, the ciphertext also incudes the 16-byte IV, so we have 3 * 16 bytes of ciphertext. We receive ciphertext in hex; applying len to it, each hex digit is counted separetly, so 3 * 16 bytes in hexadecimal results in 96 hex digits. This justifies _SIZE_ = 96. So if b = 0 is chosen, then we always have a ciphertext with 96 hex digits. If b = 1 is chosen, we have a ciphertext that has more than 96 hex digits (32 more hex digits since it's just larger by one 16 byte block).
    """

    """ Your attack code goes here.
    """
    msg0 = "0000000000000000" #16 bytes
    msg1 = "00000000000000000000000000000000" #32 bytes
    ok = ""
    for _ in range(1000):
        #print("Message 1:", msg0, ", Message 2:", msg1)
        #print(send_oracle_command(tn, msg0, msg1))
        ciphertext = send_oracle_command(tn, msg0, msg1)
        #print("Guess:", guess)
        ok = ""
        if len(ciphertext) > 96:
            ok = send_guess(tn, 1)
        else:
            ok = send_guess(tn, 0)
        #print(ok)
        if "lost" in ok:
            break
    print(ok)
    print(json_recv(tn))
    
if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50400

    #localhost:50400
#    HOSTNAME = "localhost"
#    PORT = 50400
    
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
