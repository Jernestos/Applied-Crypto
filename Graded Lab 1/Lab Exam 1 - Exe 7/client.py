from telnetlib import Telnet
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad

#Reuse of code for task m2, m3, m4, m5, m6. New code is commented. Since I just reused the previous tasks, the explaination for the corresponding code snippets/methods are the same. So you see some comments not really suited for this task.
#Note to the TA: I started with M4 task. By solving M4, I can also solved M2 and M3 by just adapting which blocks I need to decrypt. That is, instead of decrypting all ciphertext blocks (except the IV block), I only decrypt the first block. 
# For M3, that is sufficient to solve the task because the salt is 8 bytes long, or 16 hex digits, and each hex digit is represented here as 1 byte. So decrypting the first (non-IV) ciphertext block gives back the salt (in hex, as it was sent).
# In addition, for M2, instead of going through all possible padding values, I just look at the padding value == 1 because that is the only one used for the last byte of the block (last hex digit of the salt) (because the salt is 8 bytes long, or 16 hex digits, and each hex digit is represented here as 1 byte. So decrypting the first (non-IV) ciphertext block gives back the salt (in hex, as it was sent).)
#Further explaination are further down in the code.

def json_recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return json.loads(line.decode("utf-8"))

def json_send(tn: Telnet, req: dict):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")

#some copy pasted send stuff from previous tasks.
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
    
def get_encrypted_flag(tn: Telnet, value) -> str:
    json_send(tn, {"something": value})
    return json_recv(tn)["res"]

def send_encrypted_flag_command(tn: Telnet, value) -> str:
    json_send(tn, {"command": value})
    return json_recv(tn)["res"]
    
#Up until here, I just copied stuff from M0.

#Now the interesting stuff
    
def find_length_of_error_messages():
    error_messages_length_set = set({}) 
    #this set contains the length of lengths of encrypted responses
    #we know we can trigger 3 error messages as described in M1
    # we can also see that if we run the server locally and print out the error messages, just before it's encrypted
    #so we want to receive these 3 encrypted error messages to determine their lenghts.
    while len(error_messages_length_set) < 3:
        randomstuff1 = get_random_bytes(AES.block_size)
        randomstuff2 = get_random_bytes(AES.block_size)
        ctxt = randomstuff1 + randomstuff2
        #randomize message (not to trigger the exception for querying same messages)
        #We just reuse this for M3, M4, etc because it works.
        res = send_my_enc_stuff(tn, bytes.hex(ctxt)) #get encrypted response
        error_messages_length_set.add(len(res)) #add length of encrypted response to set.
    
    #biggest value in set is the utf 8 error
    #we can see that if we run the server locally and print out the error messages, just before it's encrypted
    #for more on that, this basically the code used to solve M1, so for more on that, see comments in M1
    
    #sort the values asc and convert the set into a list
    ordered_lengths = list(sorted(error_messages_length_set))
    
    #just some debugging messages.
    #print("Oracla paras : list computed: ", end="")
    #print(ordered_lengths)
    return ordered_lengths
    
def get_some_encrypted_server_message():    
    #get an encrypted message with the salt in it.
    randomstuff1 = get_random_bytes(AES.block_size)
    randomstuff2 = get_random_bytes(AES.block_size)
    ctxt = randomstuff1 + randomstuff2
    #randomize message (not to trigger the exception for querying same messages)
    #We just reuse this for M3, M4, etc. because it works.
    
    #get an encrypted message with the salt in it.
    #we just use the example given
    #res = send_my_enc_stuff(tn, "c0e70a1a2d9ad0bc0536c8b5f993fd3a9bd5020eabfb2bb093eea4b64bed4707")
    res = send_my_enc_stuff(tn, bytes.hex(ctxt))
 
    #debug info
    #print("Received message res: ", end="")
    #print(res)
    return res #hex
    
def padding_oracle(ordered_lengths, iv_block, ciphertext_block):
    #ordered_lengths: ordered lenghts of encrypted error messages
    #iv_block: iv block
    #ciphertext_block: ciphertext block
    
    #We use M1 to make a padding oracle, based on the lengths of the encrypted error messages
    #this is explained in M1.
    ctxt_to_send = bytes.hex(iv_block + ciphertext_block)
    res = send_my_enc_stuff(tn, ctxt_to_send) #hex
    if len(res) > ordered_lengths: #
        return False #no padding error, it's a UTF-8 decoding error, the longest error message.
    else:
        return True #padding error otherwise
        
def get_individual_blocks_from_ciphertext(ciphertext):
    #ciphertext: entire ciphertext, including the IV
    
    #from ciphertext in hex, get individual 16 bytes blocks
    #first 32 hex digits form the IV block, the remaining the actual ciphertext
    
    iv = bytes.fromhex(ciphertext[:32]) #in bytes, IV block
    ciphertext_remaining = ciphertext[32:] #in hex, remaining ciphertext block without IV
    num_blocks = len(ciphertext_remaining) // 32 #number of 16 byte blocks of ciphertext_remaining
    individual_ctxts = []
    for i in range(num_blocks):
        individual_ctxts.append(bytes.fromhex(ciphertext_remaining[i*32: (i + 1) * 32])) #extract individual ciphertext blocks, convert each ciphertext block into bytes and add it to the list individual_ctxts
    
    #iv in bytes
    #individual_ctxts is a list of bytes
    #num_blocks is number of 16 byte blocks, discounting the IV block
    return (iv, individual_ctxts, num_blocks) #unit: (bytes, bytes[], int)

  
def find_padding_length(ordered_lengths, iv_block, ciphertext_block):
    #assume we are dealing with here with the last ciphertext block.  
    #then the second-last block can be treated as the iv block we can modify
    #Now assume that the ciphertext_block is padded but we don't know by how many bytes
    #If we intefere from left to right with the padding by changing one byte at a time of the iv, that gets xored then with the decrypted ciphertext block, and we get a padding error for the first time, then we know that number of bytes used for padding and therefore the number of plaintext bytes (not padded)
    #e.g. if the padding is 0x04 0x04 0x04 0x04, then the plaintext block looks like P = p | 0x04 0x04 0x04 0x04, where p are 12 bytes of plaintext. Because we go from left to right, by changing the fourth-last byte in the iv, we also change the fourth-last byte in the plaintext, that is P' = p | T 0x04 0x04 0x04, where T is some byte not equal to 0x04, hence P' has an invalid padding, which we can detect using the padding oracle. Because there was an invalid padding when we tried to change the fourth-last byte, it means that there at 4 padding bytes.
    #note that going from left to right also make sure that we don't go into the edge cases
    #e.g. where true padding is 0x02 0x02 but we also get a correct padding with 0x01 as the last byte.
    
    #naturally, when applied to not the last ciphertext block, then there is no padding in it and therefore we get a padding_length of 16, indicating that the next block is the one containing all the padding bytes
 
    padding_length = 1 #there is at least 1 padding byte
    for i in range(AES.block_size - 1): #left to right meddling, i is byte pos
        i_th_iv_byte = bytes([iv_block[i]])  #the ith byte of the iv block
        modified_i_th_iv_byte = strxor(i_th_iv_byte, bytes([1])) #change i_th_iv_byte
        new_iv = iv_block[:i] + modified_i_th_iv_byte + iv_block[(i + 1):] #iv modified at pos i
        if (padding_oracle(ordered_lengths, new_iv, ciphertext_block)): #if padding oracle complains about invalid padding
            return AES.block_size - i #number of padding length
    return padding_length
    
def decrypting_block(ordered_lengths, current_ciphertext_block):
    #ordered_lengths: ordered lenghts of encrypted error messages
    #current_ciphertext_block: ciphertext block to decrypt
    
    #Consider ciphertext C | C_i, where C is previous ciphertext block, preceding C_i. Let D_i be the decryption of C_i, and P_i the plaintext corresponding to C_i (including padding). From CBC, we know C xor D_i = P_i. We have a padding oracle (from M1), telling us if the supplied ciphertext C' | C_i results in a plaintext with correct padding. We can now iterate through all possiblities (g) of the last byte of C' = c | c15 and use the padding oracle to check if C' | C_i results in a plaintext with valid padding (padding byte at last pos is 0x01). If invalid, we try a new g and query again. If valid (we found a working guess byte, g15), then we know that the last byte of D_i (d15) xored with g_correct = 0x01, that is g15 xor d15 = 0x01 => d15 = 0x01 xor g15 (call this insight S).
    #Similarly, we can now try to find the second-last byte of D_i, byte d14. We aim that the resulting plaintext has 0x02 0x02 as the last two bytes (padding). Since we know d15, we must have that last byte of C'' is equals to d15 xor 0x02 (masking operation with padding value Y, to find the Y-last byte of D_i - call this operation M) Now we need to find guess-byte g14 such that g14 xor d14 (second last byte of D_i) equals 0x02.
    #We continue so for the third last, fourth last, etc, one byte at a time until we have all found D_i. (This is what was taught in the lecture).
    #Keep in mind that to get the actual plaintext, we need to xor D_i with the previous ciphertext C to get the plaintext P_i
    
    decrypted_ciphertext = bytearray(bytes([0] * AES.block_size)) #use bytearray for read and write access, indexable, this byte array contains D_i at the end, we set it initially to zero to make the masking operation M easier.
    prev_ciphertext_modified_for_padding = bytearray(bytes([0] * AES.block_size)) #declare var
    
    for padding_value in range(1,17): #fully find entire block D_i.
        
        for guess in range(2**8): #guess all possible byte values
            prev_ciphertext_modified_for_padding[AES.block_size - padding_value] = guess #The padding_value-th-last byte of the block is set to the guess value
            #prev_ciphertext_modified_for_padding = prev_ciphertext_modified_for_padding[:16 - padding_value] + bytes([guess]) + prev_ciphertext_modified_for_padding[16 - padding_value + 1:] #note to me: causes slowdown and bugs -> to not use that
            if not padding_oracle(ordered_lengths, bytes(prev_ciphertext_modified_for_padding), current_ciphertext_block): 
                #no padding error -> padding valid
                if padding_value == 1:
                    #it can happen (edge case) that we have something like [some bytes] 0x0K 0x0K 0x0K 0x0K 0x0K [T]. Then there are two valid paddings for the byte T: 0x0K or 0x01. Then, if the guess causes an xor resulting in 0x0K first, then, for padding value == 1, this is wrong but the padding is corect. The countermeasure is to break this sequence of padding, e.g. using the second last byte of iv_used_for_padding (if we use let's say the thrid last byte, then we need to add another case distintion for padding_value == 2, doing a similar analysis) and change it and then use the resulting ciphertext block in the following query.
                    #If both (previous one and the following) querie return valid padding, then we know that the second last byte does not belong to the padding, hence 0x01 must be the correct padding, so we do not enter the following if branch and just to the next instr, the break inst, which breaks out of the guessing loop. 
                    #Else, if the following query fails, then the second byte belongs to the padding - we continue to guess. (e.g. the previous query could have resulted in a plaintext block ending in 0x02 0x02 (the first 0x02 by chance, the second 0x02 because of our guess value) - by changing the second last byte in prev_ciphertext_modified_for_padding block, we also change the second last 0x02 to another value not equal 0x02, so we would get a padding of [some_value] 0x02, which is invalid padding)
                    prev_ciphertext_modified_for_padding[14] = prev_ciphertext_modified_for_padding[14] ^ 42 #change second last byte of prev_ciphertext_modified_for_padding and give it to query.
                    #prev_ciphertext_modified_for_padding = prev_ciphertext_modified_for_padding[:14] + bytes([42]) + prev_ciphertext_modified_for_padding[15:] #causes slowdown, buggy
                    if padding_oracle(ordered_lengths, bytes(prev_ciphertext_modified_for_padding), current_ciphertext_block): #if this is true, then we have a padding error
                        continue  #keep looking for the correct guess.
                break
        #decrypted_ciphertext = decrypted_ciphertext[:AES.block_size - padding_value] + strxor(bytes([guess]), bytes([padding_value])) + decrypted_ciphertext[AES.block_size - padding_value + 1:] buggy, slowdown
        decrypted_ciphertext[AES.block_size - padding_value] = padding_value ^ guess #see S, we determine the padding_value-th-last byte of D_i
        #prev_ciphertext_modified_for_padding = strxor(bytes([padding_value] * 16), decrypted_ciphertext) #debugged
        
        #now prepare prev_ciphertext_modified_for_padding for the next iteration
        prev_ciphertext_modified_for_padding = bytearray(strxor(bytes([padding_value + 1] * AES.block_size), decrypted_ciphertext)) #This is the masking operation M. This xors all the previous found values of D_i with the next padding value (=for the 1+padding_value-th-last byte of D_i to find) such that these bytes, xored with corresponding D_i bytes, will result in byte padding byte with value 1+padding_value. for simplicity, I just xor the entire block - each byte is going to be guessed eventually, so it does not really matter that I xor the entire block instead of just the bytes of D_i learned so far.
        
    return decrypted_ciphertext #get D_i for corresponding ciphertext current_ciphertext_block, note that we don't xor unlike in prev task since we are interested in D_i and not the actual plaintext P_i

def split_plaintext(plaintext): #Split plaintext into 16 byte blocks
    #split plaintext (bytes) into blocks of 16 bytes
    blocks_of_plaintest = []
    num_blocks = len(plaintext) // 16 #number of 16 byte blocks of ciphertext_remaining
    for i in range(num_blocks):
        blocks_of_plaintest.append(plaintext[i*16: (i + 1) * 16]) 
    return blocks_of_plaintest #list of 16 bytes of blocks
    
def attack(tn: Telnet):
    """ 
    Strategy: Padding oracle attack as described in the lecture. We first setup our "padding oracle" like in M1, then get some ncrypted message (challenge) to descrypt, and then we split the ciphertext into iv, the remaining ciphertext, and the number of blocks in the entire ciphertext (discounting IV block).
    
    Then we are given the plaintext "flag_hey_there_oh_noes_block_boundaries_rip", which we want a given cyphertext to decrypt to (without given the server key). We first pad it, then we split it into 16 byte blocks. We prepend some dummy value in order to deal with indexes easier, e.g. now the new list of plaintext blocks has the property that the i_th plaintext block corresponds to the i-th ciphertext block in ciphertest_blocks (after the iv block as been prepended individual_ctxts). You could also say that the dummy value corresponds to the iv block. (this is jsust by the way).
    
    #The idea is described below.     
    Further down (and in the methods) are more comments.
    """
    print("INIT: ")
    
    #setup stuff
    ordered_lengths = find_length_of_error_messages() #find para for padding oracle
    ciphertext = get_some_encrypted_server_message() #get ciphertext
    (iv, individual_ctxts, num_blocks) = get_individual_blocks_from_ciphertext(ciphertext) #structure cipheretxt; num_blocks is number of blocks, not counting the IV block; everything is in bytes
    
    #from the server code, we need to find a ciphertext such that it decrypts to the following string (unpadded)
    #flag_hey_there_oh_noes_block_boundaries_rip
    plaintext = "flag_hey_there_oh_noes_block_boundaries_rip"
    padded_plaintext = pad(plaintext.encode(), AES.block_size) #padded plaintext now in bytes
    plaintext_blocks = [b'dummy_place_holder_to_simplyfy_index_handling'] + split_plaintext(padded_plaintext) #list of 16 byte plaintest blocks, the block at index 0 is to be disregarded
    ciphertest_blocks = [iv] + individual_ctxts #also in bytes, include iv in the ciphertext
    ciphertest_blocks = ciphertest_blocks[:len(plaintext_blocks)] #truncuate to number of plaintext blocks
    
    #strategy: We work backwards. Suppose we have ciphertet C = IV | C1 | C2 and plaintext (we want the supplied ciphertext to decrypt to) P = P1 | P2. Let decryption of C2 (just before we xor with previous ciphertext block) be D2.
    # Then we can get P2 as plaintext corresponding to C2 by setting C1_new such that C1_new XOR D2 = P2. (=> C1_new = P2 XOR D2) Then we replace C1 by C1_new.
    # Then we compute for C1_new a new D1_new with the padding oracle.
    # Then we do the same for the IV block. get P1 as plaintext corresponding to C1 by setting IV_new such that IV_new XOR D1_new = P1 (=> IV_new = P1 xor D1_new). Then we replace IV by IV_new. Then we are done. With this, the new ciphertext  C' = IV_new | C1_new | C2 will decrypt to the targeted plaintext P = P1 | P2.
    # This attack can be extended to more than just 3 cipher text blocks.
    
    #backwards, excluding the IV block.
    for block_number_i in range(len(plaintext_blocks) - 2, 0, -1): #start at the second last ciphertext block and work towards the first ciphertext block
        print("Starting modifying current ciphertext block")
        print("Starting decryption for next block")
        d_i_plus_1 = decrypting_block(ordered_lengths[1], ciphertest_blocks[block_number_i + 1])
        print("Finished decryption of current block")
        p_i_plus_1 = plaintext_blocks[block_number_i + 1] #good to have a dummy entry, otherwise, we need to do more complex index handling.
        new_c_i = strxor(d_i_plus_1, p_i_plus_1)
        ciphertest_blocks[block_number_i] = new_c_i
        print("Finished modifying current ciphertext block")
        
    #now for the new iv block, "i = 0"
    print("Starting modifying current ciphertext block")
    print("Starting decryption for next block")
    d_i_plus_1 = decrypting_block(ordered_lengths[1], ciphertest_blocks[1])
    p_i_plus_1 = plaintext_blocks[1]
    new_c_i = strxor(d_i_plus_1, p_i_plus_1)
    ciphertest_blocks[0] = new_c_i
    print("Finished decryption of current block")
    
    
    #concatenate the new ctxt blocks
    ciphertest_to_send = b''
    for c in ciphertest_blocks:
        ciphertest_to_send = ciphertest_to_send + c
    
    ciphertest_to_send = bytes.hex(ciphertest_to_send) #convert it to hex
    #now we have a new ciphertext that decrypt to flag_hey_there_oh_noes_block_boundaries_rip on the server side
    res = send_encrypted_flag_command(tn, ciphertest_to_send) #we get an encrypted response, with the flag in it
    print("res: ", end="")
    print(res)
    print("-" * 20)
    (iv, individual_ctxts, num_blocks) = get_individual_blocks_from_ciphertext(res) #structure cipheretxt; num_blocks is number of blocks, not counting the IV block; everything is in bytes
    
    decrypted_message = b''
    
    #we can safely assume that we are dealing here with blocks such that there is at least 2 a "truly" ciphertext, in addition to the IV. This can be seen by size of the encrypted messages the server sends back.
    number_of_padding_bytes = find_padding_length(ordered_lengths[1],individual_ctxts[-2],individual_ctxts[-1]) 
    previous_ciphertext_block = iv
    for current_ciphertext_block in individual_ctxts:
        print("Starting decryption for next block")
        decrypted_block = decrypting_block(ordered_lengths[1], current_ciphertext_block) #block d_i
        xored_decrypted_block = strxor(decrypted_block, previous_ciphertext_block) #plaintext block p_i
        decrypted_message = decrypted_message + xored_decrypted_block #add plaintext block p_i to already already found plaintext blocks.
        previous_ciphertext_block = current_ciphertext_block
        print("Finished decryption of current block")
    print("Decrypted message contains the flag:")
    print(decrypted_message[:-number_of_padding_bytes].decode())
    print("-" * 20)
    
if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50406

    #localhost:50400
#    HOSTNAME = "localhost"
#    PORT = 50406
    
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)