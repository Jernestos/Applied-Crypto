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

    encrypted = iv_original + ctxt
    
    block_number = len(encrypted)//AES.block_size
    decrypted = bytes()
    # Go through each block
    for i in range(block_number, 0, -1):
        current_encrypted_block = encrypted[(i-1)*AES.block_size:(i)*AES.block_size]
        # At the first encrypted block, use the initialization vector if it is known
        if(i == 1):
            previous_encrypted_block = bytearray(IV.encode("ascii"))
        else:
            previous_encrypted_block = encrypted[(i-2)*AES.block_size:(i-1)*AES.block_size]
        bruteforce_block = previous_encrypted_block
        current_decrypted_block = bytearray(iv_original.encode("ascii"))
        padding = 0
        # Go through each byte of the block
        for j in range(AES.block_size, 0, -1):
            padding += 1
            # Bruteforce byte value
            for value in range(0,256):
                bruteforce_block = bytearray(bruteforce_block)
                bruteforce_block[j-1] = (bruteforce_block[j-1] + 1) % 256
                joined_encrypted_block = bytes(bruteforce_block) + current_encrypted_block
                # Ask the oracle
                res = send_my_enc_stuff(tn, bytes.hex(joined_encrypted_block))
                if(len(res) > ordered_lengths[1]):
                    current_decrypted_block[-padding] = bruteforce_block[-padding] ^ previous_encrypted_block[-padding] ^ padding
                    # Prepare newly found byte values
                    for k in range(1, padding+1):
                        bruteforce_block[-k] = padding+1 ^ current_decrypted_block[-k] ^ previous_encrypted_block[-k]
                    break
        decrypted = bytes(current_decrypted_block) + bytes(decrypted)
    
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
