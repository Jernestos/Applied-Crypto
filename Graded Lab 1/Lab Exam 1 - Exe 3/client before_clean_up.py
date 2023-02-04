from telnetlib import Telnet
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

#Essentially, the code for M2, M3, and M4 don't differ too much.
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
    #We just reuse this for M3 and M4 because it works.
    
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
    return (iv, individual_ctxts, num_blocks) #bytes, bytes, int

  
def find_padding_length(ordered_lengths, iv_block, ciphertext_block):
    #assume we are dealing with here with the last ciphertext block.  
    #then the second last block can be treated as the iv block we can modify
    #Now assume that the ciphertext_block is padded but we don't know by how much
    #If we intefere from left to right with the padding by changing one byte at a time of the iv, that gets xored then with the decrypted ciphertext block, and we get a padding error for the first time, then we know that number of bytes used for padding and therefore the number of plaintext bytes (not padded)
    #also, this gives us a way to deal with edge cases, e.g. where true padding is 0x02 0x02 but we also get a correct padding with 0x01 as the last byte - by determinig the number of padding bytes, we can already see (and exclude) such "false positives"
    
    #naturally, when applied to not the last ciphertext block, then there is no padding in it and therefore we get a padding_length of 16, indicating that the next block is the one containing all the padding bytes
 
    padding_length = 1 #there is at least 1 padding byte
    for i in range(AES.block_size - 1): #left to right meddling, i is byte pos
        i_th_iv_byte = bytes([iv_block[i]])  #the ith byte of the iv block
        modified_i_th_iv_byte = strxor(i_th_iv_byte, bytes([1])) #change i_th_iv_byte
        new_iv = iv_block[:i] + modified_i_th_iv_byte + iv_block[(i + 1):] #iv modified at pos i
        if (padding_oracle(ordered_lengths, new_iv, ciphertext_block)): #if padding oracle complains about faulty padding
            return AES.block_size - i #number of padding length
    return padding_length

def decrypting_block(ordered_lengths, current_ciphertext_block):
#ordered_lengths: ordered lenghts of encrypted error messages
#current_ciphertext_block: ciphertext block to decrypt
#idea: there are to blocks, the previous ciphertext block PREV_C and the current ciphertext block CURR_C. Call the decryption of CURR_C D.
# by cbc decryption, we can manipulate PREV_C to control the padding of the plaintext P because we xor D with PREV_C. So I do just what is shown in the lecture, starting with a padding of 1, then 2, then 3 bytes, etc.
#it doesn't really matter what IV we use to control the padding, we just need to adapt accordingly. We choose an IV, which is initially all zero, because, when we are done with the decryption, hence this IV is modified, then xoring D with this IV yields a block of 16 bytes with the 0 value. This can only happen if D is equal to this IV.
#So we compute D one byte at a time, from right to left.
    ziv = bytes([0] * 16)
    for padding_value in range(1, 2):
        #there are [1,2,3...,16] padding values but we are only interesting in the last byte of the block, by description of the flag, to extract the salt byte.
        iv_used_for_padding = bytes([padding_value] * 16)
        #padding block full of padding bytes. We are only interest in the position ith position from the right, so doesn't matter if it's an entire block full of paddings not needed  
        for guess in range(256):
            #at the position we are interest, we guess the byte such that the resulting plaintext has a valid padding.
            new_iv = iv_used_for_padding[:len(iv_used_for_padding) - padding_value] + bytes([guess]) + iv_used_for_padding[len(iv_used_for_padding) - padding_value + 1:]
            if not padding_oracle(ordered_lengths, new_iv, current_ciphertext_block):
                if padding_value == 1:
                    #it can happen (edge case) that we have something like [some bytes] 0x0K 0x0K 0x0K 0x0K 0x0K [T]. Then there are two valid paddings for the byte T: 0x0K or 0x01. Then, if the guess causes an xor resulting in 0x0K first, then, for padding value == 1, this is wrong. The countermeasure is to break this sequence of padding, e.g. using the second last byte of iv_used_for_padding and change it and then use it in the query.
                    #If both (previous one and the following) querie return valid padding, then we know that the second last byte does not belong to the padding, hence 0x01 is the correct padding, as we wanted. Else, if the following query fails, then the second byte belongs to the padding - we continue to guess.
                    new_new_iv = new_iv[:-2] + bytes([1]) + new_iv[-1:] #debugged
                    if padding_oracle(ordered_lengths, new_new_iv, current_ciphertext_block):
                        continue  #we have to keep guessing.
                print("Success - guess: " + str(guess))
                break
        temp = strxor(bytes([guess]), bytes([padding_value]))
        ziv = ziv[:len(ziv) - padding_value] + temp + ziv[len(ziv) - padding_value + 1:]
        #as described aboe, ziv, at the end should have the following property:
        #ziv xor D = 0 => D = ziv. This allows us to recover the plaintext D.
    return ziv
    #returns decryption of current_ciphertext_block
    
def decrypting_block__(ordered_lengths, current_ciphertext_block):
#ordered_lengths: ordered lenghts of encrypted error messages
#current_ciphertext_block: ciphertext block to decrypt

#idea: there are to blocks, the previous ciphertext block PREV_C and the current ciphertext block CURR_C. Call the decryption of CURR_C D.
# by cbc decryption, we can manipulate PREV_C to control the padding of the plaintext P because we xor D with PREV_C. So I do just what is shown in the lecture, starting with a padding of 1, then 2, then 3 bytes, etc.

#it doesn't really matter what IV we use to control the padding, we just need to adapt accordingly. We choose an IV, which is initially all zero, because, when we are done with the decryption, hence this IV is modified, then xoring D with this IV yields a block of 16 bytes with the 0 value. This can only happen if D is equal to this IV.

#So we compute D one byte at a time, from right to left.
    zeroing_iv = [0] * 16
    ziv = bytes([0] * 16)
    
    for padding_value in range(1, 2):
        #there are [1,2,3...,16] padding values but we are only interesting in the last byte of the block, by description of the flag, to extract the salt byte.
        print("padding_value: ", end="")
        print(padding_value)
        padding_iv = [padding_value ^ b for b in zeroing_iv]
        iv_used_for_padding = bytes([padding_value] * 16)
        #padding block full of padding bytes. We are only interest in the position ith position from the right, so doesn't matter if it's an entire block full of paddings not needed  
        for guess in range(256):
            #at the position we are interest, we guess the byte such that the resulting plaintext has a valid padding.
            padding_iv[-padding_value] = guess
            iv = bytes(padding_iv)
            
            new_iv = iv_used_for_padding[:len(iv_used_for_padding) - padding_value] + bytes([guess]) + iv_used_for_padding[len(iv_used_for_padding) - padding_value + 1:]#debugged
#            new_iv = iv_used_for_padding[:-padding_value] + bytes([guess]) + iv_used_for_padding[-(padding_value) + 1:] 
            #print(iv_used_for_padding)
            #print(guess)
            if not padding_oracle(ordered_lengths, new_iv, current_ciphertext_block):
                if padding_value == 1:
                    #it can happen (edge case) that we have something like [some bytes] 0x0K 0x0K 0x0K 0x0K 0x0K [T]. Then there are two valid paddings for the byte T: 0x0K or 0x01. Then, if the guess causes an xor resulting in 0x0K first, then, for padding value == 1, this is wrong. The countermeasure is to break this sequence of padding, e.g. using the second last byte of iv_used_for_padding and change it and then use it in the query.
                    #If both (previous one and the following) querie return valid padding, then we know that the second last byte does not belong to the padding, hence 0x01 is the correct padding, as we wanted. Else, if the following query fails, then the second byte belongs to the padding - we continue to guess.
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    new_new_iv = new_iv[:-2] + bytes([1]) + new_iv[-1:] #debugged
                    if padding_oracle(ordered_lengths, new_new_iv, current_ciphertext_block):
                        continue  #we have to keep guessing.
                print("Success - guess: " + str(guess))
                break
        temp = strxor(bytes([guess]), bytes([padding_value]))
        ziv = ziv[:len(ziv) - padding_value] + temp + ziv[len(ziv) - padding_value + 1:]
#        ziv = ziv[:-padding_value] + temp + ziv[-(padding_value) + 1:]
        zeroing_iv[-padding_value] = guess ^ padding_value
        #as described aboe, ziv, at the end should have the following property:
        #ziv xor D = 0 => D = ziv. This allows us to recover the plaintext D.
        print("zeroing_iv:\t", end="")
        print(bytes(zeroing_iv))
        print("ziv:\t\t", end="")
        print(ziv)
        
    return ziv
    #returns decryption of current_ciphertext_block

def decrypting_block_(ordered_lengths, current_ciphertext_block):
    #ordered_lengths: ordered lenghts of encrypted error messages
    #current_ciphertext_block: ciphertext block to decrypt
    
    #idea: there are to blocks, the previous ciphertext block PREV_C and the current ciphertext block CURR_C. Call the decryption of CURR_C D.
    # by cbc decryption, we can manipulate PREV_C to control the padding of the plaintext P because we xor D with PREV_C. So I do just what is shown in the lecture, starting with a padding of 1, then 2, then 3 bytes, etc.
    
    #it doesn't really matter what IV we use to control the padding, we just need to adapt accordingly. We choose an IV, which is initially all zero, because, when we are done with the decryption, hence this IV is modified, then xoring D with this IV yields a block of 16 bytes with the 0 value. This can only happen if D is equal to this IV.
    
    #So we compute D one byte at a time, from right to left.

    ziv = bytes([0] * AES.block_size)
    for padding_value in range(1, 2): 
        #there are [1,2,3...,16] padding values but we are only interesting in the last byte of the block, by description of the flag, to extract the salt byte.
        iv_used_for_padding = bytes([padding_value] * AES.block_size) #padding block full of padding bytes. We are only interest in the position ith position from the right, so doesn't matter if it's an entire block full of paddings not needed       
        for guess in range(256):
            #at the position we are interest, we guess the byte such that the resulting plaintext has a valid padding.
            new_iv = iv_used_for_padding[:len(iv_used_for_padding) - padding_value] + bytes([guess]) + iv_used_for_padding[len(iv_used_for_padding) - padding_value + 1:]
            #not using a new name (new_iv and new_new_iv) causes a slowdown - not sure why
            #print(guess)
            if not padding_oracle(ordered_lengths, new_iv, current_ciphertext_block):
                if padding_value == 1:
                    #it can happen (edge case) that we have something like [some bytes] 0x0K 0x0K 0x0K 0x0K 0x0K [T]. Then there are two valid paddings for the byte T: 0x0K or 0x01. Then, if the guess causes an xor resulting in 0x0K first, then, for padding value == 1, this is wrong. The countermeasure is to break this sequence of padding, e.g. using the second last byte of iv_used_for_padding and change it and then use it in the query.
                    #If both (previous one and the following) querie return valid padding, then we know that the second last byte does not belong to the padding, hence 0x01 is the correct padding, as we wanted. Else, if the following query fails, then the second byte belongs to the padding - we continue to guess.
                    new_new_iv = new_iv[:-2] + bytes([1]) + new_iv[-1:]
                    if padding_oracle(ordered_lengths, new_new_iv, current_ciphertext_block):
                        continue  #we have to keep guessing.
                print(" - Succcess guess: " + str(guess))
                break
       
        temp = strxor(bytes([guess]), bytes([padding_value]))
        ziv = ziv[:len(ziv) - padding_value] + temp + ziv[len(ziv) - padding_value + 1:]
        #as described aboe, ziv, at the end should have the following property:
        #ziv xor D = 0 => D = ziv. This allows us to recover the plaintext D.
    return ziv
    #returns decryption of current_ciphertext_block
   
def attack(tn: Telnet):
    """ 
    Strategy: Padding oracle attack as described in the lecture. We first setup our "padding oracle" like in M1, then get some ncrypted message (challenge) to descrypt, and then we split the ciphertext into iv, the remaining ciphertext, and the number of blocks in the entire ciphertext (discounting IV block).
    Then we need to find the number of bytes used to pad the original messsage. This is done by find_padding_length. We compute that so that when we get the plaintext (including the padding bytes), we can just unpad it to get the original plaintext.
    
    Then we decrypt each ciphertext block (except the IV block) one at a time. When we get each descrypted block, we have to xor it with the previous ciphertext block (in the case of the first ciphertext block, the previous one is the IV block)       
    """
    #print("INIT: ")
    #decryption of entire ciphertext happens here
    #setup stuff
    ordered_lengths = find_length_of_error_messages() #find para for padding oracle
    
    #start guessing game
    for _ in range(3000):
        ciphertext = get_some_encrypted_server_message() #get ciphertext
        (iv, individual_ctxts, num_blocks) = get_individual_blocks_from_ciphertext(ciphertext) #structure cipheretxt; num_blocks is number of blocks, not counting the IV block; everything is in bytes
        decrypted_message = b''
        previous_ciphertext_block = iv
        current_ciphertext_block = individual_ctxts[0] #the salt is in the first non-iv block
        print("Starting decryption for next block")
        decrypted_block = decrypting_block(ordered_lengths[1], current_ciphertext_block)
        xored_decrypted_block = strxor(decrypted_block, previous_ciphertext_block)
        decrypted_message = decrypted_message + xored_decrypted_block
        print("Finished decryption of current block")
        print("Ascii number of last salt byte: ", end="")
        print(chr(decrypted_message[15]))
        res = send_guess(tn, chr(decrypted_message[15]))
        if "lost" in res:
            print("lost")
            break
        else:
            print(res)
        print('-'*20)
    print(json_recv(tn))
    
    
if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50402

    #localhost:50400
    HOSTNAME = "localhost"
    PORT = 50402
    
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
