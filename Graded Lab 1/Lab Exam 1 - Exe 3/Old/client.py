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
    print(ordered_lengths)
    
    #get an encrypted message with the salt in it.
    randomstuff1 = get_random_bytes(AES.block_size)
    randomstuff2 = get_random_bytes(AES.block_size)
    ctxt = randomstuff1 + randomstuff2
    res = send_my_enc_stuff(tn, bytes.hex(ctxt))
    
    print("res: ", end="")
    print(res)
    #1 block is 16 bytes long, this is 32 hex digits.
    #so we need 2 blocks, one for the iv and one for the plaintext with the salt in it. By inspection, the salt is the first thing that appears in the plaintext block.
    
    iv_original, ctxt = bytes.fromhex(res[:32]), bytes.fromhex(res[32:64])
    
    print("Original IV: ", end="")
    print(iv_original)
    
    print("ctxt: ", end="")
    print(ctxt)
    
    padding = bytes([0] * AES.block_size)
    zeroing_iv = bytes([0] * AES.block_size)
    
#    print("-" * 20)
#    print(iv_original)
#    print(ctxt)
#    print(padding)
#    print(zeroing_iv)
#    print("-" * 20)
    
    #guess the last byte
    for guess in range(256):
        iv = iv_original[:-1] + bytes([guess])
        ctxt_to_send = iv + ctxt
        #print(iv)
        res = send_my_enc_stuff(tn, bytes.hex(ctxt_to_send))[16:]
        if len(res) >= ordered_lengths[1]: #decoding error, not a padding one -> we got the right padding
            #print(res)
            print("Good padding with: " + str(guess))
            padding_01 = padding[:-1] + bytes([1])
            zeroing_iv = strxor(padding_01, iv)
            print("zeroing_iv:", end="")
            print(bytes.hex(zeroing_iv))
            print("zeroing_iv len: ", end="")
            print(len(zeroing_iv))
            break
    
    salt_byte = zeroing_iv[15]
    res = send_guess(tn, salt_byte)
    print(res)
    
#    print("-" * 20)
#    print(iv_original)
#    print(ctxt)
#    print(padding)
#    print(zeroing_iv)
#    print("-" * 20)
#    
#    for index in range(2,17): #want the last salt byte, byte pos 7 of ciphertext (omitting iv)
#        print("Index: " + str(index))
#        padding_last_index_bytes = padding[:-(index - 1)] + bytes([index] * (index - 1))
#        for_iv = strxor(padding_last_index_bytes, zeroing_iv)
#        print("PADDING: ", end="")
#        print(padding_last_index_bytes)
#        print("for_iv: ", end="")
#        print(for_iv)
##        break
#        for guess in range(256):
#            #print("Index: " + str(index) + " guess: " + str(guess))
#            iv = for_iv[:-index] + bytes([guess]) + for_iv[-(index - 1):]
#            #print("IV: ", end="")
#            #print(iv)
#            ctxt_to_send = iv + ctxt
#            res = send_my_enc_stuff(tn, bytes.hex(ctxt_to_send))
#            
#            if len(res) == ordered_lengths[1]: #decoding error, not a padding one -> we got the right padding
#                print("Index: " + str(index) + " guess: " + str(guess) + " Good padding.")
#                padding_index = padding[:-index] + bytes([index] * index)
#                print(padding_index)
#                zeroing_iv = strxor(padding_index, iv)
#                break
#    salt_byte = zeroing_iv[15]
#    print(salt_byte)
#    res = send_guess(tn, salt_byte)
#    print(res)
    
    
    
        
if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50402

    #localhost:50400
    HOSTNAME = "localhost"
    PORT = 50402
    
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
