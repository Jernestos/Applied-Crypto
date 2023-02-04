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
    
    
def find_length_of_error_messages():
    error_messages_length_set = set({})
    #we know we can trigger 3 error messages as described above
    #so we want to receive these 3 encrypted error messages to determine their lenghts.
    while len(error_messages_length_set) < 3:
        randomstuff1 = get_random_bytes(AES.block_size)
        randomstuff2 = get_random_bytes(AES.block_size)
        ctxt = randomstuff1 + randomstuff2
        res = send_my_enc_stuff(tn, bytes.hex(ctxt))
        error_messages_length_set.add(len(res))
    
    #biggest is utf 8 error
    ordered_lengths = list(sorted(error_messages_length_set)) #ascendingly sorted
    print("List computed: ", end="")
    print(ordered_lengths)
    return ordered_lengths
    
def get_some_encrypted_server_message():    
    #get an encrypted message with the salt in it.
    randomstuff1 = get_random_bytes(AES.block_size)
    randomstuff2 = get_random_bytes(AES.block_size)
    ctxt = randomstuff1 + randomstuff2
    #get an encrypted message with the salt in it.
    #we just use the example given
    #res = send_my_enc_stuff(tn, "c0e70a1a2d9ad0bc0536c8b5f993fd3a9bd5020eabfb2bb093eea4b64bed4707")
    res = send_my_enc_stuff(tn, bytes.hex(ctxt))
 
    print("Received res: ", end="")
    print(res)
    return res #hex
    
def padding_oracle(ordered_lengths, iv_block, ciphertext_block):
    ctxt_to_send = bytes.hex(iv_block + ciphertext_block)
    res = send_my_enc_stuff(tn, ctxt_to_send) #hex
    if len(res) > ordered_lengths[1]:
        return False #no padding error
    else:
        return True #padding error
        
def get_individual_blocks_from_ciphertext(ciphertext):
    #from ciphertext in hex, get individual blocks in bytes
    #first 32 hex digits form the IV block, the remaining the actual ciphertext
    
    iv = bytes.fromhex(ciphertext[:32]) #bytes
    ciphertext_remaining = ciphertext[32:] #hex
    num_blocks = len(ciphertext_remaining) // 32
    individual_ctxts = []
    for i in range(num_blocks):
        individual_ctxts.append(bytes.fromhex(ciphertext_remaining[i*32: (i + 1) * 32])) #bytes
    return (iv, individual_ctxts, num_blocks) #bytes, bytes, int


#def get_last_byte_of_block(ordered_lengths, iv_block, ciphertext_block):
#    for guess in range(256):
#        new_iv = iv[:AES.block_size - 1] + bytes([guess])
#        if not padding_oracle(ordered_lengths, new_iv, ciphertext_block):
#            new_iv = iv[:AES.block_size - 1] + strxor(bytes([guess]), bytes([iv_block[-1]]))
#            return new_iv
#    return iv_block
#    
#
#def get_decrypted_bytes_of_a_block(ordered_lengths, iv_block, ciphertext_block):
#    #here, what we are doing is, after figuring out the number of bytes used to pad, use those and the lecture material to find the decrypted bytes of the bytes at positions where the padding occurs
#    padding_length = find_padding_length(ordered_lengths, iv_block, ciphertext_block)
#    decypted_bytes = []
#    
#    offset = AES.block_size - padding_length #this is the position where padding starts
#    for i in range(padding_length):
#        i_th_iv_byte = bytes([iv_block[offset + i]])
#        decypted_bytes.append(strxor(i_th_iv_byte, bytes([padding_length])))
#    return decypted_bytes
#    

#def decrypt_byte_before(ordered_lengths, iv_block, ciphertext_block, bytes_learned):
#    number_of_bytes_learned = len(bytes_learned)
#
#
#def decrypt_1_block(ordered_lengths, iv_block, ciphertext_block):
#    decrypted_block = []
#    decrypted_padding_bytes = get_decrypted_bytes_of_a_block(ordered_lengths, iv_block, ciphertext_block)
#    number_of_bytes_decrypted = len(decrypted_padding_bytes)
#    decrypted_block = number_of_bytes_decrypted #need to prepend stuff
#    for pos in range(AES.block_size - number_of_bytes_decrypted - 1, -1, -1):
#        pass
#    
def find_padding_length(ordered_lengths, iv_block, ciphertext_block):
    #assume we are dealing with here with the last ciphertext block.  
    #then the second last block can be treated as the iv block we can modify
    #Now assume that the ciphertext_block is padded but we don't know by how much
    #If we intefere from left to right with the padding by changing one byte at a time of the iv, that gets xored then with the decrypted ciphertext block, and we get a padding error for the first time, then we know that number of bytes used for padding and therefore the number of plaintext bytes (not padded)
    #also, this gives us a way to deal with edge cases, e.g. where true padding is 0x02 0x02 but we also get a correct padding with 0x01 as the last byte - by determinig the number of padding bytes, we can already see (and exclude) such "false positives"
    
    #naturally, when applied to not the last ciphertext block, then there is no padding in it and therefore we get a padding_length of 16, indicating that the next block is the one containing all the padding bytes
 
    padding_length = 1 #there is at least 1 padding byte
    for i in range(AES.block_size - 1): #left to right meddling, i is byte pos
        i_th_iv_byte = bytes([iv_block[i]]) 
        modified_i_th_iv_byte = strxor(i_th_iv_byte, bytes([1])) #change i_th_iv_byte
        new_iv = iv_block[:i] + modified_i_th_iv_byte + iv_block[(i + 1):] #iv modified at pos i
        if (padding_oracle(ordered_lengths, new_iv, ciphertext_block)): #if padding oracle complains about faulty padding
            return AES.block_size - i #number of padding length
    return padding_length
    


#decrypted_block = decrypt_single_block(ordered_lengths, previous_block, current_block)

#This is the first iteration (last byte of a block) of finding the correct guess.
#we aim to find the correct guess such that the last byte of the plaintext is 0x01, that is a correct padding. So what we are doing here to to find a IV such that IV xored (decrypted ciphertext_block) yields a valid padding
def get_last_byte_of_block(ordered_lengths, iv, ciphertext_block):
    for guess in range(256):
        new_iv = iv[:-1] + bytes([guess])
        if not padding_oracle(ordered_lengths, new_iv, ciphertext_block):
            #no padding error
            new_iv = iv[:-1] + strxor(bytes([guess]), bytes([iv[-1]]))
            print("Last byte - Success! with: ", end="")
            print(str(guess))
            return new_iv
    return iv
            
#here, we begin try to learn the plaintext bytes that re in the position of the padding bytes.
#We first compute the number of padding bytes of the current  ctxt block, ciphertext_block.
#Then we can infer how the padding looks like, e.g. if number is 3, then the padding is 0x03 0x03 0x03
#This number enables us to learn the decrypted bytes (as presented in the lecture) at the positions in which the padding bytes are
def get_few_last_byte_of_block(ordered_lengths, iv_old, ciphertext_block):
    iv = get_last_byte_of_block(ordered_lengths, iv_old, ciphertext_block)
    #so we have learned information about the last byte. Using this, we can learn more about the other bytes, here we begin with bytes in the padding positions (split due to debugging)
    
    number_of_padding_bytes = find_padding_length(ordered_lengths,iv,ciphertext_block)
    number_of_padding_bytes_in_bytes_unit = bytes([number_of_padding_bytes])
    
    pos_at_which_padding_starts = AES.block_size - number_of_padding_bytes
    bytes_learned = b''
    
    for padding_byte_index_pos in range(number_of_padding_bytes):
        temp = bytes([iv[pos_at_which_padding_starts + padding_byte_index_pos]])
        bytes_learned = bytes_learned + strxor(temp, number_of_padding_bytes_in_bytes_unit)
    return bytes_learned
    
#learn other bytes, at non-padding positions (split due to debugging)
def learn_byte(ordered_lengths, previous_block, current_block, bytes_learned): #learn 1 byte
    number_of_bytes_learned = len(bytes_learned)
    #iv = previous_block.copy()
    
    mask = bytes([0] * (AEs.block_size - (number_of_bytes_learned + 1))) + bytes([number_of_bytes_learned + 1] * (number_of_bytes_learned + 1)) #want a valid padding for (number_of_bytes_learned + 1) many padding bytes that is padding byte is (number_of_bytes_learned + 1), this is what I am for.
    iv = strxor(bytes_learned, mask) #apply mask, with the aim to get a plaintext with the targeted padding
    
    pos_to_learn = AEs.block_size - (number_of_bytes_learned + 1)
    target_byte = iv[pos_to_learn]
    
    for guess in range(256):
        iv = iv[:pos_to_learn] + strxor(bytes([guess]), bytes([target_byte])) + iv[(1 + pos_to_learn):]
        if not padding_oracle(ordered_lengths, iv, current_block):
            #no padding oracle error
            temp = strxor(bytes([guess]), bytes([(number_of_bytes_learned + 1)]))
            ret = strxor(bytes([target_byte]), temp)
            return ret
        
        
def decrypt_single_block(ordered_lengths, previous_block, current_block):
    bytes_already_learned = get_few_last_byte_of_block(ordered_lengths, previous_block, current_block)
    print("Bytes we learned so far in the padding position: ", end="")
    print(bytes_already_learned)
    
    number_of_bytes_already_learned= len(bytes_already_learned)
    print("number_of_bytes_already_learned: ", end="")
    print(number_of_bytes_already_learned)
    
    decrypted_block = bytes_already_learned #so far we got these bytes
    print("decrypt_single_block - decrypted_block: ", end="")
    print(decrypted_block)

    for pos_in_block in range(AES.block_size - number_of_bytes_already_learned - 1, -1, -1): #iterate  from right to left and find new bytes for byte at pos_in_block; #learn one byte at a time
        byte_learned = learn_byte(ordered_lengths, previous_block, current_block, bytes_already_learned)
        decrypted_block = byte_learned + decrypted_block
        bytes_already_learned = decrypted_block
    return decrypted_block
        
    
def attack(tn: Telnet):
    """ 
    Strategy: Like like the previous task, we figure out if it is a decoding error or a padding error.               
    """
    
    #decryption of entire ciphertext happens here
    #setup stuff
    ordered_lengths = find_length_of_error_messages() #find para for padding oracle
    ciphertext = get_some_encrypted_server_message() #get ciphertext
    (iv, individual_ctxts, num_blocks) = get_individual_blocks_from_ciphertext(ciphertext) #structure cipheretxt; num_blocks is number of blocks, not counting the IV block; everything is in bytes
    
    decrypted_stuff = b''
    
    #we can safely assume that we are dealing here with blocks such that there is at least 2 a "truly" ciphertext, in addition to the IV
    number_of_padding_bytes = find_padding_length(ordered_lengths,individual_ctxts[-2],individual_ctxts[-1]) #determine the number of padding bytes
    print("SETUP:")
    print("Ciphertext in hex: ", end="")
    print(ciphertext)
    print("iv: ", end="")
    print(iv)
    print("individual ctxt: ", end="")
    print(individual_ctxts)
    print("num blocks: ", end="")
    print(num_blocks)
    print("number of padding bytes: ", end="")
    print(number_of_padding_bytes)
    
    print("-" * 20)
    
    previous_block = iv
    for block_number_i in range(num_blocks): #iterate through blocks
        print("block_number_i: " + str(block_number_i))  
        current_block = individual_ctxts[block_number_i] #get block block_number_i, in bytes
        print("current block: ", end="")
        print(current_block)
        decrypted_block = decrypt_single_block(ordered_lengths, previous_block, current_block) #decrypt block
        print("decrypted block: ", end="")
        print(decrypted_block)
        #decrypted_block = strxor(decrypted_block, previous_block) #final xor to get the plaintext
        #print("xored decrypted block: ", end="")
        #print(decrypted_block)
        
        previous_block = current_block #set prev block to act as the iv
        decrypted_stuff = decrypted_stuff + decrypted_block #append newly plaintext to result
        print("-" * 20)
        
    plaintext_without_padding = decrypted_stuff[:-number_of_padding_bytes] #unpad padding
    print((bytes.hex(plaintext_without_padding)))
    
if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50402

    localhost:50400
    HOSTNAME = "localhost"
    PORT = 50402
    
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
