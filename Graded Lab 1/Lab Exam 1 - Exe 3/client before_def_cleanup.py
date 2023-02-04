from telnetlib import Telnet
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

#Essentially, the code for M2, M3, etc. don't differ too much. New, task specific changes are well commented
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

def send_guess(tn: Telnet, salt_byte: str) -> str:
    json_send(tn, {"guess": salt_byte})
    return json_recv(tn)["res"]
    
    
def send_my_enc_stuff(tn: Telnet, value_to_send) -> str:
    json_send(tn, {"command": value_to_send})
    return json_recv(tn)["res"]

#Up until here, I just copied stuff from M0.
#not really interesting.

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
        #We just reuse this for M3 and M4 because it works.
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


def decrypting_block(ordered_lengths, prev_ciphertext, current_ciphertext_block):
    #ordered_lengths: ordered lenghts of encrypted error messages
    #current_ciphertext_block: ciphertext block to decrypt
    
    #Consider ciphertext C | C_i, where C is previous ciphertext block, preceding C_i. Let D_i be the decryption of C_i, and P_i the plaintext corresponding to C_i (including padding). From CBC, we know C xor D_i = P_i. We have a padding oracle (from M1), telling us if the supplied ciphertext C' | C_i results in a plaintext with correct padding. We can now iterate through all possiblities (g) of the last byte of C' = c | c15 and use the padding oracle to check if C' | C_i results in a plaintext with valid padding (padding byte at last pos is 0x01). If invalid, we try a new g and query again. If valid (we found a working guess byte, g15), then we know that the last byte of D_i (d15) xored with g_correct = 0x01, that is g15 xor d15 = 0x01 => d15 = 0x01 xor g15 (call this insight S).
    #Similarly, we can now try to find the second-last byte of D_i, byte d14. We aim that the resulting plaintext has 0x02 0x02 as the last two bytes (padding). Since we know d15, we must have that last byte of C'' is equals to d15 xor 0x02 (masking operation with padding value Y, to find the Y-last byte of D_i - call this operation M) Now we need to find guess-byte g14 such that g14 xor d14 (second last byte of D_i) equals 0x02.
    #We continue so for the third last, fourth last, etc, one byte at a time until we have all found D_i. (This is what was taught in the lecture).
    #Keep in mind that to get the actual plaintext, we need to xor D_i with the previous ciphertext C to get the plaintext P_i
    
    decrypted_ciphertext = bytearray(bytes([0] * AES.block_size)) #use bytearray for read and write access, indexable, this byte array contains D_i at the end, we set it initially to zero to make the masking operation M easier.

    for padding_value in range(1,2): #we only care about the last byte of the salt, which is the last byte of the first non-iv ciphertext block. No need to fully find entire block D_i, yet.
        #prev_ciphertext_modified_for_padding = strxor(bytes([padding_value] * 16), decrypted_ciphertext) #debugged
        prev_ciphertext_modified_for_padding = bytearray(strxor(bytes([padding_value] * AES.block_size), decrypted_ciphertext)) #This is the masking operation M. This xors all the previous found values of D_i with the current padding value (=for the padding_value-th-last byte of D_i to find) such that these bytes, xored with corresponding D_i bytes, will result in byte padding byte with value padding_value. for simplicity, I just xor the entire block - each byte is going to be guessed eventually, so it does not really matter that I xor the entire block instead of just the bytes of D_i learned so far.
        
        for guess in range(256): #guess all possible byte values
            prev_ciphertext_modified_for_padding[-padding_value] = guess #The padding_value-th-last byte of the block is set to the guess value
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
        
    return strxor(prev_ciphertext,bytes(decrypted_ciphertext)) #get plaintext for corresponding ciphertext current_ciphertext_block
#    
#    
#def decrypting_block_nope(ordered_lengths, current_ciphertext_block):
#    
#    zeroing_iv = bytes([0] * AES.block_size)
#    
#    for pad_val in range(1,2):
#        padding_iv = strxor(bytes([pad_val] * AES.block_size), zeroing_iv)
#        
#        for candidate in range(256):
#            temp = padding_iv[:AES.block_size - pad_val] + bytes([candidate]) + padding_iv[AES.block_size - pad_val + 1:]
#            padding_iv = temp
#            iv = padding_iv
#            if not padding_oracle(ordered_lengths, iv, current_ciphertext_block):
#                if pad_val == 1:
#                    # make sure the padding really is of length 1 by changing
#                    # the penultimate block and querying the oracle again
#                    
#                    temp = padding_iv[:-2] + bytes([1]) + padding_iv[-1:] #debugged
#                    padding_iv = temp
#                    iv = padding_iv
#                    if padding_oracle(ordered_lengths, iv, current_ciphertext_block):
#                        continue  # false positive; keep searching
#                break
#        temp = strxor(bytes([candidate]), bytes([pad_val]))
#        zeroing_iv = zeroing_iv[:AES.block_size - pad_val] + temp + zeroing_iv[AES.block_size - pad_val + 1:]
#        #as described aboe, ziv, at the end should have the following property:
#        #ziv xor D = 0 => D = ziv. This allows us to recover the plaintext D.
#    return zeroing_iv
#    
#def decrypting_block_works(ordered_lengths, current_ciphertext_block):   
#    # zeroing_iv starts out nulled. each iteration of the main loop will add
#    # one byte to it, working from right to left, until it is fully populated,
#    # at which point it contains the result of DEC(ct_block)
#    zeroing_iv = [0] * 16
#
#    for pad_val in range(1, 2):
#        padding_iv = [pad_val ^ b for b in zeroing_iv]
#
#        for candidate in range(256):
#            padding_iv[-pad_val] = candidate
#            iv = bytes(padding_iv)
#            if not padding_oracle(ordered_lengths, iv, current_ciphertext_block):
#                if pad_val == 1:
#                    # make sure the padding really is of length 1 by changing
#                    # the penultimate block and querying the oracle again
#                    padding_iv[-2] ^= 1
#                    iv = bytes(padding_iv)
#                    if padding_oracle(ordered_lengths, iv, current_ciphertext_block):
#                        continue  #we have to keep guessing.
#                break
#        zeroing_iv[-pad_val] = candidate ^ pad_val
#        #as described aboe, ziv, at the end should have the following property:
#        #ziv xor D = 0 => D = ziv. This allows us to recover the plaintext D.
#    return bytes(zeroing_iv)
#    
#def decrypting_block_(ordered_lengths, current_ciphertext_block):
##ordered_lengths: ordered lenghts of encrypted error messages
##current_ciphertext_block: ciphertext block to decrypt
##idea: there are to blocks, the previous ciphertext block PREV_C and the current ciphertext block CURR_C. Call the decryption of CURR_C D.
## by cbc decryption, we can manipulate PREV_C to control the padding of the plaintext P because we xor D with PREV_C. So I do just what is shown in the lecture, starting with a padding of 1, then 2, then 3 bytes, etc.
##it doesn't really matter what IV we use to control the padding, we just need to adapt accordingly. We choose an IV, which is initially all zero, because, when we are done with the decryption, hence this IV is modified, then xoring D with this IV yields a block of 16 bytes with the 0 value. This can only happen if D is equal to this IV.
##So we compute D one byte at a time, from right to left.
#    ziv = bytes([0] * 16)
#    for padding_value in range(1, 2):
#        #there are [1,2,3...,16] padding values but we are only interesting in the last byte of the block, by description of the flag, to extract the last salt byte.
#        temp = bytes([padding_value] * 16)
#        iv_used_for_padding = strxor(temp, ziv)
#        #padding block full of padding bytes. We are only interest in the position ith position from the right, so doesn't matter if it's an entire block full of paddings not needed  
#        for guess in range(256):
#            #at the position we are interest, we guess the byte such that the resulting plaintext has a valid padding.
#            new_iv = iv_used_for_padding[:len(iv_used_for_padding) - padding_value] + bytes([guess]) + iv_used_for_padding[len(iv_used_for_padding) - padding_value + 1:]
#            if not padding_oracle(ordered_lengths, new_iv, current_ciphertext_block):
#                if padding_value == 1:
#                    #it can happen (edge case) that we have something like [some bytes] 0x0K 0x0K 0x0K 0x0K 0x0K [T]. Then there are two valid paddings for the byte T: 0x0K or 0x01. Then, if the guess causes an xor resulting in 0x0K first, then, for padding value == 1, this is wrong. The countermeasure is to break this sequence of padding, e.g. using the second last byte of iv_used_for_padding and change it and then use it in the query.
#                    #If both (previous one and the following) querie return valid padding, then we know that the second last byte does not belong to the padding, hence 0x01 is the correct padding, as we wanted. Else, if the following query fails, then the second byte belongs to the padding - we continue to guess.
#                    new_new_iv = new_iv[:-2] + bytes([1]) + new_iv[-1:] #debugged
#                    if padding_oracle(ordered_lengths, new_new_iv, current_ciphertext_block):
#                        continue  #we have to keep guessing.
#                #print("Success - guess: " + str(guess))
#                break
#        temp = strxor(bytes([guess]), bytes([padding_value]))
#        ziv = ziv[:len(ziv) - padding_value] + temp + ziv[len(ziv) - padding_value + 1:]
#        #as described aboe, ziv, at the end should have the following property:
#        #ziv xor D = 0 => D = ziv. This allows us to recover the plaintext D.
#    return ziv
#    #returns decryption of current_ciphertext_block
#
#def decrypting_block_original(ordered_lengths, current_ciphertext_block):
##ordered_lengths: ordered lenghts of encrypted error messages
##current_ciphertext_block: ciphertext block to decrypt
##idea: there are to blocks, the previous ciphertext block PREV_C and the current ciphertext block CURR_C. Call the decryption of CURR_C D.
## by cbc decryption, we can manipulate PREV_C to control the padding of the plaintext P because we xor D with PREV_C. So I do just what is shown in the lecture, starting with a padding of 1, then 2, then 3 bytes, etc.
##it doesn't really matter what IV we use to control the padding, we just need to adapt accordingly. We choose an IV, which is initially all zero, because, when we are done with the decryption, hence this IV is modified, then xoring D with this IV yields a block of 16 bytes with the 0 value. This can only happen if D is equal to this IV.
##So we compute D one byte at a time, from right to left.
#    ziv = bytes([0] * 16)
#    for padding_value in range(1, 2):
#        #there are [1,2,3...,16] padding values but we are only interesting in the last byte of the block, by description of the flag, to extract the salt byte.
#        iv_used_for_padding = strxor(bytes([padding_value] * 16), ziv)
#        #padding block full of padding bytes. We are only interest in the position ith position from the right, so doesn't matter if it's an entire block full of paddings not needed  
#        for guess in range(256):
#            #at the position we are interest, we guess the byte such that the resulting plaintext has a valid padding.
#            temp = iv_used_for_padding[:16 - padding_value] + bytes([guess]) + iv_used_for_padding[16 - padding_value + 1:]
#            iv_used_for_padding = temp #without temp, it does not work
#            if not padding_oracle(ordered_lengths, iv_used_for_padding, current_ciphertext_block):
#                if padding_value == 1:
#                    #it can happen (edge case) that we have something like [some bytes] 0x0K 0x0K 0x0K 0x0K 0x0K [T]. Then there are two valid paddings for the byte T: 0x0K or 0x01. Then, if the guess causes an xor resulting in 0x0K first, then, for padding value == 1, this is wrong. The countermeasure is to break this sequence of padding, e.g. using the second last byte of iv_used_for_padding and change it and then use it in the query.
#                    #If both (previous one and the following) querie return valid padding, then we know that the second last byte does not belong to the padding, hence 0x01 is the correct padding, as we wanted. Else, if the following query fails, then the second byte belongs to the padding - we continue to guess.
#                    #new_new_iv = new_iv[:-2] + bytes([1]) + new_iv[-1:] #debugged
#                    new_new_iv = iv_used_for_padding[:14] + bytes([1]) + iv_used_for_padding[15:]
#                    iv_used_for_padding = new_new_iv #again, without this temporary var, it does not work
#                    if padding_oracle(ordered_lengths, iv_used_for_padding, current_ciphertext_block):
#                        continue  #we have to keep guessing.
#                #print("Success - guess: " + str(guess))
#                break
#                
#        temp = strxor(bytes([guess]), bytes([padding_value]))
#        ziv = ziv[:16 - padding_value] + temp + ziv[16 - padding_value + 1:]
#        #as described aboe, ziv, at the end should have the following property:
#        #ziv xor D = 0 => D = ziv. This allows us to recover the plaintext D.
#    return ziv
#    #returns decryption of current_ciphertext_block

def attack(tn: Telnet):
    """ 
    Strategy: Padding oracle attack as described in the lecture. We first setup our "padding oracle" like in M1, then get some encrypted message (challenge) to descrypt, and then we split the ciphertext into iv, the remaining ciphertext, and the number of blocks in the entire ciphertext (discounting IV block).
    Then we need to find the number of bytes used to pad the original messsage. This is done by find_padding_length. We compute that so that when we get the plaintext (including the padding bytes), we can just unpad it to get the original plaintext.
    
    Then we decrypt each ciphertext block (except the IV block) one at a time. When we get each descrypted block, we have to xor it with the previous ciphertext block (in the case of the first ciphertext block, the previous one is the IV block) to get the actual plaintext. (The methods used are described more in detail above). Also the oracle padding attack was described in the lecture.
    
    Here, we don't know the server key used to encrypt a message, what we do know how to decrypt multiple ciphetext blocks using the oracle padding attack (also shown in lecture)
    
    #for more explaination, see the methods or below. This is just the core of the idea, how to use the padding oracle for decryption.
    
    """
    #print("INIT: ")
    #decryption of entire ciphertext happens here
    #setup stuff
    ordered_lengths = find_length_of_error_messages() #find para for padding oracle
    
    #start guessing game and win 1000 times by finding the correct last salt byte.
    for _ in range(1000):
        ciphertext = get_some_encrypted_server_message() #get ciphertext
        (iv, individual_ctxts, num_blocks) = get_individual_blocks_from_ciphertext(ciphertext) #structure cipheretxt; num_blocks is number of blocks, not counting the IV block; everything is in bytes
        decrypted_message = b''
        previous_ciphertext_block = iv
        current_ciphertext_block = individual_ctxts[0] #the salt is in the first non-iv block, so we only care about this particular block and disregard the other non-iv ctxt blocks
        #print("Starting decryption for next block")
        decrypted_block = decrypting_block(ordered_lengths[1], previous_ciphertext_block, current_ciphertext_block) #we get plaintext P_i.
        decrypted_message = decrypted_message + decrypted_block #add newly found plaintext to the plaintexts we have found so far.
        #print("Finished decryption of current block")
        #print("Ascii number of last salt byte: ", end="")
        res = chr(decrypted_message[15]) #we are only interseted in the last byte of the salt block
        #print(res)
        res = send_guess(tn, res)
        if "lost" in res:
            print("lost")
            break
        else:
            print(res)
        #print('-'*20)
    print(json_recv(tn))
    
    #flag{ASpectreIsHauntingCrypto3bfb0efe886d94cdac0e7344d0580c1a}
    #flag{ASpectreIsHauntingCrypto950a76e71f1dde9478079b2a7c48027a}
    
if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50402

    #localhost:50400
#    HOSTNAME = "localhost"
#    PORT = 50402
    
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
