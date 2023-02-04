from telnetlib import Telnet
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

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

def send_guess(tn: Telnet, salt_byte: int) -> str:
    json_send(tn, {"guess": salt_byte})
    return json_recv(tn)["res"]
    
    
def send_my_enc_stuff(tn: Telnet, value_to_send) -> str:
    json_send(tn, {"command": value_to_send})
    return json_recv(tn)["res"]

def attack(tn: Telnet):
    """ 
    Strategy: Like like the previous task, we figure out if it is a decoding error or a padding error.               
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
    
    #biggest_length = sorted(error_messages_length_set)[len(error_messages_length_set) - 1]
    
    #ordered_lengths = [192,224,320]
    #biggest is utf 8 error
    ordered_lengths = list(sorted(error_messages_length_set))
    print("List computed: ", end="")
    print(ordered_lengths)
    
    #get an encrypted message with the salt in it.
    randomstuff1 = get_random_bytes(AES.block_size)
    randomstuff2 = get_random_bytes(AES.block_size)
    ctxt = randomstuff1 + randomstuff2
    res = send_my_enc_stuff(tn, bytes.hex(ctxt))
 
    print("Received res: ", end="")
    print(res)
    #1 block is 16 bytes long, this is 32 hex digits.
    #so we need 2 blocks, one for the iv and one for the plaintext with the salt in it. By inspection, the salt are the first 8 bytes that appear in the plaintext block.
    
    iv_original, ctxt = bytes.fromhex(res[:32]), bytes.fromhex(res[32:64])
    
    print("Original IV in hex:\t", end="")
    print(bytes.hex(iv_original))
    
    print("Original IV in bytes:\t", end="")
    print(iv_original)
    
    print("ctxt=salt in hex:\t", end="")
    print(bytes.hex(ctxt))
    
    print("ctxt=salt in bytes:\t", end="")
    print(ctxt)
    
    iv = bytes([0] * AES.block_size)
    padding = bytes([0] * AES.block_size)
    ziv = bytes([0] * AES.block_size)
    #guess last byte
    i = 1
    flag = False
    for guess in range(256):
        iv = iv[:-i] + bytes([guess])
        ctxt_to_send = bytes.hex(iv + ctxt)
        res = send_my_enc_stuff(tn, ctxt_to_send)
        if len(res) > ordered_lengths[1] and not flag: #decoding error, not a padding one -> we got the right padding
                #print(res)
            iv_test_second_last_byte = iv[:-2] + strxor(bytes([iv[-2]]), bytes([1]))+ bytes([iv[-1]])
            ctxt_to_send = bytes.hex(iv_test_second_last_byte + ctxt)
            res = send_my_enc_stuff(tn, ctxt_to_send)
            if not (len(res) > ordered_lengths[1]):
                pass
            else:
                print(str(i) + " " + "Good padding with: " + str(guess))
                padding = padding[:-i] + bytes([i] * i)
                ziv = strxor(padding, iv)
    #                break #break causes weird behaviour when sending guess
                flag = True
    padding = bytes([0] * (AES.block_size - i)) + bytes([i + 1] * i)
    print("Padding: ", end="")
    print(padding)
    
    for i in range(2, 16):
        #i = 2
        flag = False
        iv = strxor(padding, ziv)
        for guess in range(256):
            iv = iv[:-i] + bytes([guess]) + iv[-(i - 1):]
            ctxt_to_send = bytes.hex(iv + ctxt)
            res = send_my_enc_stuff(tn, ctxt_to_send)
            if len(res) > ordered_lengths[1] and not flag: #decoding error, not a padding one -> we got the right padding
                #print(res)
                print(str(i) + " " + "Good padding with: " + str(guess))
                padding = padding[:-i] + bytes([i] * i)
                print("Padding 1: ", end="")
                ziv = strxor(padding, iv)
                print(padding)
#                break #break causes weird behaviour when sending guess
                flag = True
        if i != 16:
            print("Padding 2: ", end="")
            padding = bytes([0] * (AES.block_size - i)) + bytes([i + 1] * i)
            print(padding)
            
    print("ziv in bytes: ", end="")
    print(ziv)
    print("ziv in hex: ", end="")
    print(bytes.hex(ziv))
    last_salt_byte = bytes([ziv[7]])
    print("Last_salt_byte: ", end="")
    print(last_salt_byte)
    last_salt_byte_hex = bytes.hex(last_salt_byte)
    print("Last_salt_byte_hex: ", end="")
    print(last_salt_byte_hex)
    print("Send: ", end="")
    print(last_salt_byte_hex[1])
    res = send_guess(tn, last_salt_byte_hex[1])
    print(res)
    
    
    
        
if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50402

    #localhost:50400
    HOSTNAME = "localhost"
    PORT = 50402
    
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
