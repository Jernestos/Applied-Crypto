import json
from typing import Optional
from telnetlib import Telnet

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import DSS

from Crypto.Signature.DSS import DeterministicDsaSigScheme
from Crypto.Random import random
from Crypto.Util.number import *

import time #this is allowed since it's part of the standard library

#note to ta: the high level overview is in a big comment at the end of the file. details are in the appropriate methods.

#import numpy as np
#from echelon import *

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

#for collection signatures and error messages
#this flag is for distingishuing when we are collection signatures and when we are not doing so, because we use json_signed_recv for two cases: when we are collecting signatures and their corresponding error messages, and when we are receiving the flag. In the former case, COLLECTING is turned on (True), hence we save them. In the latter case, we do not need to collect the flag and its signature, so it's off (False)
#initially set to True because we want to start with collecting. (see below why)
COLLECTING = True


#note that we do not reimplement a slightly different version of json_signed_recv and json_signed_send since doign this via these flags is easier.

'''

From https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&rep=rep1&type=pdf I know how the verification and singing works.

m: message

Signing is also described here: https://datatracker.ietf.org/doc/html/rfc6979#section-2.4

Signing(d, m), where d is the secret key
h = Hash(m)
k = h XOR d
r = (k * G).x , whre G is base point of curve NIST P-256, and .x is taking x coordinate
s = k^(-1) * (h + d * r) mod q
(r, s) is signature 


Verify(Q, m), where Q is the public key

h = Hash(m)
s1 = s^(-1) mod q
r' = ((h * s1) * G + (r * s1) * Q).x taking x coordinate
check if r' == r

'''

def convert_signature_to_tuple(signature):
    #according to https://github.com/Legrandin/pycryptodome/blob/1be081a77234cd989f9180cab8921243e4f44171/lib/Crypto/Signature/DSS.py#L106 when signing, here, in this case, we convert the point-coordinates to byte sequences and then concatenate them.
    #convert_signature_to_tuple does the inverse
    #the order is prsumably (r,s), as described here https://datatracker.ietf.org/doc/html/rfc6979#section-2.2 (also in abeove link)
    
    #observe that signature is 64 bytes long (tested)
    #so we can split it up into 32 bytes chunks
    r, s = signature[:32], signature[32:]
    return (r, s)
    
#this list contains hashes of messages and signatures, from the server
#hash of plaintexts using sha256, and convert signatures to (r,s) tuple via convert_signature_to_tuple
#these are messages from the server
list_of_messages_received_from_server = []
'''
NIST P-256 has the following parameters (lecture slides and https://www.secg.org/SEC2-Ver-1.0.pdf)

a,b curve parameters
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


GF(p), p prime with
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
G = (Gx, Gy) "Generator point" / base point

Curve has order q, odd prime
q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

'''
'''
From G, and comparing it to the carpet_pubkey Point Q, we see that they are different -> Q = d * G, where d is the secret key of carpet, and Q the public key.

'''

'''
NIST P-256 parameters
'''

a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

#CarpetRemote code copy pasted from M3.0
class CarpetRemote():
    def __init__(self, tn: Telnet, carpet_key: EccKey, cloud_key: EccKey):
        self.tn = tn
        self.carpet_key = carpet_key
        self.cloud_key = cloud_key
        self.identity = "carpet_cloud"

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")

    def json_signed_send(self, req: dict):
        #print("START json_signed_send START")
        #print("*" * 20)
        #print("req: ", end="")
        #print(req)
        req_hash = SHA256.new(json.dumps(req).encode()) #json dictionary, command, encoded
        # Your code here.
        #I omitted comments from M3.0
        signature = DSS.new(self.cloud_key, 'fips-186-3').sign(req_hash)
        #print("signature: ", end="")
        #print(signature)
        #print("END json_signed_send END")
        #print("*" * 20)
        
        
        '''
        Why do we use carpet and not self.identity (= carpet_cloud)? This is explainted at the end of the file in a huge comment section.
        '''
        self.json_send({
            "identity": "carpet", #originally self.identity
            "msg": req,
            "signature": signature.hex()
        })

    def json_signed_recv(self):
        res = self.json_recv()
        #print("*" * 20)
        #print("START json_signed_recv START")
        #print("res: ", end="")
        #print(res)
        
        #when turned out we collect signatures (and the corresponding hash value) in a list
        #when it's turned of, then we do not collect signatures (and the corresponding hash value)
        global COLLECTING
        if COLLECTING:
            #collect messages and signatures and store them in list_of_messages_received_from_server
            #this list contains hashes of messages and signatures, from the server
            #hash the "plaintext" using sha256, and convert signatures to (r,s) tuple via convert_signature_to_tuple
            list_of_messages_received_from_server.append((SHA256.new(res["signed_error"].encode()).digest(), convert_signature_to_tuple(bytes.fromhex(res["signature"]))))
        signature = bytes.fromhex(res["signature"])

        if "signed_res" in res:
            signed = json.dumps(res["signed_res"]).encode()
        else:
            signed = res["signed_error"].encode()

        h = SHA256.new(signed)
        
        #coments from M3.0 omitted
        
        # Your code here.

        verifier = DSS.new(self.carpet_key, 'fips-186-3')
        #print("END json_signed_recv END")
        #print("*" * 20)
        try:
            verifier.verify(h, signature)
            return signed
        except ValueError as e:
            print("Client side: json_signed_recv Value error:")
            error_text = ": error: " + type(e).__name__ + ": " + str(e)
            return error_text

        #return signed
        
    def get_flag(self):
        #note that this method is very similiar to the method get_status; it just has another command, the command "backdoor" to get the flag. Basically, if get_status works, then get_flag should also work.
        obj = {
            "command": "backdoor"
        }
        global COLLECTING
        COLLECTING = False
        self.json_signed_send(obj)
        res = self.json_signed_recv()
        return res
    
    #unused comments.
    def get_status(self):
        obj = {
            "command": "get_status"
        }
        self.json_signed_send(obj)
        res = self.json_signed_recv()
        return res
            
    def get_256_signatures(self):
        #this method is used to collect 256 different hash values and their corresponding signatures
        #we set collection to true, so that when we receive responses from the server, we store those in the list (after processing the response)
        global COLLECTING
        COLLECTING = True
        #the nonce is 32 bytes (by inspection on server code) -> 256 bits
        for i in range(256):
            print(str(i) + ". query sent:")
            self.get_status()
            #print(self.get_status())
            time.sleep(1)
        #since each error message we receive as a timestamp, we have to wait at least 1 second to get a new message (if we wait shorter, don't wait, we get the same message -> same hash value and same signatures), in order to avoid collecting multple identical hash values (and multiple corresponding same signature values). 1 second is the minimum time to wait (and since we have a time limit of 5 minutes, we cannot afford to wait too long for each message), because the server gives us the timestamp up to the second.
        #print(list_of_messages_received_from_server)
        return "Finished retrieving 256 unique signatures."
    
    def set_new_private_key(self, d_secretkey):
        #after figuring out the priate key d_secretkey, we can finally set it as our cloud_key.
        self.cloud_key = ECC.construct(curve="NIST P-256", d=d_secretkey)
        #note to myself; turn off collecting signatures and erroe messages
        #because have have the private key now.
        return "Private key set"
        
    
def convert_bit_sequence_to_int(d):
    #convert bit sequence to integer value
    #note that the left most list entry corresponds to the least signifint bit
    res = 0
    power_of_2 = 1
    for i in range(len(d)):
        res += power_of_2 * d[i]
        power_of_2 = power_of_2 * 2
    print("d value: ",end="")
    print(res)
    return res

#helper function to determine if we really have unique values
#to check if the signatures and hash values obtained are truly unique
#used during testing, not used in submission because there is a time limit
#and i already have used 256 seconds for gathering 256 signatures and hash values out of the 300 seconds
def check_unique_elements():
    hash_msg_list = []
    tuple_list = []
    for i in range(len(list_of_messages_received_from_server)):
        hash_msg, (r, s) = list_of_messages_received_from_server[i]
        hash_msg_list.append(hash_msg)
        tuple_list.append((r,s))
        
    hash_set = set(hash_msg_list)
    tuple_set = set(tuple_list)
    
    print(len(hash_set))
    print(len(tuple_set))
    #if both values are 256, then we have 256 unique elements
        
#copy pasted from echelon.py, adapted non non-numpy version, because there are some issues with int, np.int64, etc., -> instead of np, use lists
def row_echelon_form(M, q):
    lead = 0
    rowCount = len(M)
    columnCount = len(M[0])
    for r in range(rowCount):
        if lead >= columnCount:
            return
        i = r
        while M[i][lead] == 0:
            i += 1
            if i == rowCount:
                i = r
                lead += 1
                if columnCount == lead:
                    return

        M[i], M[r] = M[r], M[i].copy()

        lv = M[r][lead]
        #M[r] = [(pow(lv, -1, p) * mrx) % p for mrx in M[r]]; does not work for me, 2nd argument cannot be -1
        M[r] = [( inverse(lv, q) * mrx) % q for mrx in M[r]]
        for i in range(rowCount):
            if i != r:
                lv = M[i][lead]
                M[i] = [(iv - lv * rv) % q for rv, iv in zip(M[r], M[i])]
        lead += 1
    return M
    
def extract_solution_of_augmented_matrix(aug_mat, q):
    #augmat has 256 rows, and 257 cols, the rightmost column is the "y vector", call it y'
    #so augmat is of the form M' | y', where M' is the row echelon form matrix, applied to M | y, and right most column removed.
    #now we solve M' * vector_d = y', by working backwards, that is begin from the most bottom row / congruence equation / constraint, solve it for the unkown bit d_i and use it for the congruence equations above, etc. -. we basically reconstruct the solution backwards by substitutin, beginning from bottom and working to top most row; like it was taught in linear algebra lecture.

    vector_d = [0] * 256 #init with 0
    for row in range(255,-1,-1):
        #we don't want to perform backwards subsitution, solving for the vector_d, reducing aug_mat to a identity matrix | vector_d, just to read out the vector_d again from aug_mat. So what we do is we extract vector_d element by element and compute the solution on these eextracted elements. Essentially, all the computation is done on vector_d, as if it was the right most column of aug_mat
        vector_d[row] = aug_mat[row][256] #right most column of aug_mat, current row row; essentially just the value of the y' vector corresponding to the same row
        
        #since we solve vector_d backwards, it means that, as soon as we know its entries, we can start subtracting a scalar, given by the apporpriate entry of the matrix aug_mat, times the value of vector_d we already have solved, from both sides. Essentially, we work towards zeroing out every entry to the right of the current pivot element. of course modulo q.
        
        for col in range(row + 1, 256):
            d_value_times_coef = ( (aug_mat[row][col] % p) * (vector_d[col] % q) ) % q
            vector_d[row] = (vector_d[row] - d_value_times_coef) % q
        
        #we want pivot element to be 1, so take multiplicative inverse on both sides modulo q
        pivot_value = aug_mat[row][row]
        vector_d[row] = (inverse(pivot_value, q) * (vector_d[row] % q)) % q
    #in the end, the right most column of aug_mat (if we did not copy it out to vector_d) would contain vector_d, but we already extracted this, so no need to do that now.
    return vector_d
    
def build_matrix_solve_for_d():
    '''
    Since d is 32 bytes (8 * 32 = 256 bits) (server code inspection), we need at least 256 (unique) equations to determine each bit d_i of te secret key d. So we have a matrix M of dimension 256 x 256, the solution vector d' (which contains the bits of d), and M*d' = y, where y is the vector consisting of values h * (s - 1) mod q, one entry for each signature query.
    
    list_of_messages_received_from_server has all the information needed to build matrix and vector
    
    '''
    
    #build RHS
    list_y = []
    #y = np.empty(256)
    for i in range(len(list_of_messages_received_from_server)):
        hash_msg, (r, s) = list_of_messages_received_from_server[i]
        h_long = bytes_to_long(hash_msg)
        s_long = bytes_to_long(s)
        list_y.append((((s_long - 1) % q) * (h_long % q)) % q)
        #y[i] = (((s_long - 1) % p) * (h_long % p)) % p
        #list_y.append(h_long * (s_long - 1))
    
    #y = np.array(list_y)
    
    #print(len(y))
    
    #build LHS, the matrix M
    mat = []
    #M = np.empty((256,256))
    for row in range(len(list_of_messages_received_from_server)):
        hash_msg, (r, s) = list_of_messages_received_from_server[row]
        h_long = bytes_to_long(hash_msg) % q
        s_long = bytes_to_long(s) % q
        r_long = bytes_to_long(r) % q
        power_of_2 = 1
        cur_row = []
        temp = r_long - s_long #efficiency
        for col in range(256):
            h_i = (h_long >> col) & 1
            if h_i == 1: #effiency
                coef = ((power_of_2 % q) * ((temp + (2 * s_long) % q) % q) % q) # ((2 * h_i - 1) * s_long + r_long)
                #M[row][col] = ((power_of_2 % p) * ((temp + (2 * s_long) % p) % p) % p) # ((2 * h_i - 1) * s_long + r_long)
            else:
                coef = ((power_of_2 % q) * (temp % q)) % q # ((2 * h_i - 1) * s_long + r_long)
                #M[row][col] = ((power_of_2 % p) * (temp % p)) % p # ((2 * h_i - 1) * s_long + r_long)
            #h_i = (h_long >> col) & 1 #get i-th bit of h
            #M[row][col] = power_of_2 * (temp + h_i * 2 * s_long) # ((2 * h_i - 1) * s_long + r_long)
            power_of_2 = ((power_of_2 % q) * 2) % q
            #M[row][col] = coef
            cur_row.append(coef)
        
        #we are given row_echelon_form method -> hint for augmentation of matrix with a vector
        #augment matrix by y vector, row by row
        cur_row.append(list_y[row])
        mat.append(cur_row)
    
    '''
    After vector y and matrix mat setup, we have concaneated them to M | y to get an augmented matrix so we can use row echelon form on it.
    
    '''
    
    print("Compute solution: Start with REF")
    aug_mat_after_ref = row_echelon_form(mat, q)
    print(aug_mat_after_ref)
    print("Compute solution: solve for vector d")
    vector_d = extract_solution_of_augmented_matrix(aug_mat_after_ref, q)

    #make sure entries are mod q, 
    #for debugging purposes, unused since vector_d consists of  values 1 or 0
#    for i in range(len(vector_d)):
#        vector_d[i] = (vector_d[i] % q)
    return vector_d
    

def interact(tn: Telnet, carpet_key: EccKey, carpet_cloud_key: Optional[EccKey]):
    """ Get the flag here.
    """
    
    '''
    From server code:
        """This is ECDSA signature scheme with deterministic nonces.
        You don't need to fully understand this code. You can trust that this is
        a correct implementation of ECDSA as described in FIPS 186-4,
        except for the nonce computation, which works as follows:
                nonce = H(m) xor d

        Note that this differs from RFC6979 (and from the derandomized ECDSA you
        saw in the lectures).

        If you want to see the full implementation, refer to:
        https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Signature/DSS.py
        """
        
        """Generate k in a deterministic way.
        RFC6979 suggests a way to achieve this, but it is way too complicated!
        Here we provide a greatly simplified method: nonce = H(m) xor d
        """
        
        I suspect that changing something from what is "recommended" by RFC6979, which presumably is that the nonce has to be generated in a cryptographically secure way, to something that simple might indicate that this is where the vulneability lies.
        
        By outputting several stats (add print statements in server code, and run it locally), I can see that d is 32 bytes, and the hash values produced by SHA256, are also 32 bytes long.
        
    '''
 
    '''
    High overview on situation (details at end of file)
    Observation
    Issuing my own private key does not work because the server replies with "Invalid signature".
    Everytime I, the client, issue a command, a signature based on my private key is computed and sent to the server, which checks it with my public key.
    Observe that I do not send my public key to the server, so the server does not know my public key, hence cannot verify that the validity of the signature (even though I signed it) - because the server does not have the corresponding public key.
    The server has some sort of public key, and because the carpet_cloud_key (my private key) is not given, I think that it's safe to assume that I have to find the secret key d (because I know what curve is used, I know the base point, hence it really boils down to finding d, or to be more precise, the correct carpet_cloud_key).
    #actually, see below, almost at the bottom of the file, to read more about this conclusion.
    
    Information at disposal - summary:
    I can query commands for which I receive signatures for error messages (from remote server), signed by server's secret key
    ECDSA scheme -> I know how signing/verify works;  https://datatracker.ietf.org/doc/html/rfc6979 and https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Signature/DSS.py explain some details (signing/veryfing outlined above)
    Curve: NIST P-256
        -> hence we know what curve parameters we have
    I know that the nonce k = Hash(m) xor d, where m is the message
        -> Due to the hint and this way to making the nonce, I assume for now that this is where the vulneability lies (I cannot control the value of Hash(m) but I now m and which hash algorithm is used; the nonce itself is not returned to the client, so I cannot make k xor hash(m) = d.
        -> due to knowing the hash algorithm, I know the length of the nonce (32 bytes), and the length of d (also 32 bytes), otherwise, we would need some kind of padding for the xor operation
    There is the hint: a + b = (a XOR b) + 2 * (a AND b)
    The hint also involves row echelon form -> matrix; we might have to solve for a vector, which could be the solution or is a step towards the solution (don't know that yet); whenever a matrix is involved, is means that we have to satisfy multiple constraints at the same time (for existence of a solution; I assume there is a solution), if it is unique, I don't know -> depends on matrix
    From lecture I know:
        ECDSA has same reliance as DSA on per-signature nonce, with fatal loss of security if same nonce is used twice. (note: for different messages)
            - Also vulnerable to attacks based on partial knowledge of nonces.
            - ECDSA has an unfortunate malleability property: if (r,s) is a valid
        Since the nonce k = Hash(m) xor d, and Hash() is a collision resistant hash function, unlikely to get same nonce for two different messages (which I cannot control which messages on the server side)
        (r, s) signature for message m and verification key vk, then so is (r,-s).
    Needed to win this challenge: the secret key, corresponding to the public key the server has.
        -> with secret key, I can sign my flag command and get the flag
        
    Issue: how to get the secret key out of signatures.
    
    
    Idea: Let's math it out using the little bits of math we were given as hint (because there is only one place in the signing/veryfing computation where xor is used: in signing, to compute the nonce k, which is seen by in server code.
    
    
    We have, by signing algorithm, the following for s.
    s = k^(-1) * (h + d * r) mod q ., where h = Hash(m). Let's ignore mod q for the moment (for simplicity)
    
    s = k^(-1) * (h + d * r)
    <->
    s*k = h + d * r
    <-> (substitute nonce k for its definition k = h XOR d)
    s*( h XOR d ) = h + d * r
    <-> (hint) a + b = (a XOR b) + 2 * (a AND b) (<=>  a + b  - 2 * (a AND b) = (a XOR b))
    s*(h + d - 2 * (h AND d)) = h + d * r
    <->
    s*h + s*d - 2*s*(h AND d) = h + d*r
    <->
    h(s - 1) + d(s - r) = 2 * s *(h AND d)
    <-> (unknown d on one side)
    h(s - 1) = 2 * s * (h AND d) - d*(s - r)
    
    using the implications of a matrix (multiple constraints to be satisfied), it means that there must be multiple equations for d.
    Noticing that we are still operating with AND (bit-wise); I hazard a guess on how to proceed (note that I keep that here, even if it turns out to be the wrong ansatz, to show that I gave the challenge some thought):
        
    Let's write also bit-wise (binary): Let |d| be 32 * 8  (recall: d is 32 bytes, 1 byte is 8 bits)
    
    Recall that natural numbers can be written as a sum of powers of 2
    Then d = sum(from i = 0 to |d|) d_i * 2^i, where d_i is i-th bit of d
    
    For (h AND d), consider that h_i AND d_i (where h_i is the i-th bit of h) = 1 iff h_i = d_i = 1, else 0.
    define a = h AND d (note that since h and d are 32 bytes, a is 32 bytes as well). Then
    a = sum(from i = 0 to |a|) a_i * 2^i = sum(from i = 0 to |d|) (d_i * h_i) * 2^i.
    
    h(s - 1) = 2 * s * (h AND d) - d*(s - r) <->
    h(s - 1) = 2 * s * [sum(from i = 0 to |d|) (d_i * h_i) * 2^i] - (s - r) * [sum(from i = 0 to |d|) d_i * 2^i]
    <->
    h(s - 1) =  [sum(from i = 0 to |d|) (d_i * h_i) * 2^i * 2 * s] - [sum(from i = 0 to |d|) d_i * 2^i * (s - r)]
    <->
    h(s - 1) =  [sum(from i = 0 to |d|) (d_i * h_i) * 2^i * 2 * s - d_i * 2^i * (s - r)]
    <->
    h(s - 1) =  [sum(from i = 0 to |d|) d_i * 2^i * (h_i * 2s - (s - r))]
    <->
    h(s - 1) =  [sum(from i = 0 to |d|) d_i * 2^i * (s * (2*h_i - 1) + r)]
    
    Now, this is only 1 equation for one triple (h, (r, s)) but we have 256 many d_i bits because d is a 256 bit number. So we need at least 256 triples (h, (r, s)) to determine all of the bits of d. So we have 256 constraints / equations which gives rise to a matrix. We convert this 256 equations into a linear system of equations.
    From this, we can write it as some matrix mat, times the unknown bit vector (representing d) vector_d = y, the vector for (h(s- 1)) values.
    Then, hoping that the matrix mat is invertible (it is, we have collected 256 different signatures and hash vales, and by testing, it indeed is), we solve for the unknown vector vector_d, convert it to an integer, and use that value (the secret key is finally found) to set a new private key, and query the flag.
    because now, by knowing the secret key, we can sign the command with the correct value and are able to get the flag.
    '''
    
    if carpet_cloud_key is None:
    #if carpet_cloud_key == None: #on python3.10, this does not work, use the above
        carpet_cloud_key = EccKey(curve='NIST P-256', d=2) #does not really matter what we put here.
    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)

    #collect 256 unique hash and signature values
    print(cr.get_256_signatures())
    
    #unused, only for debugging used
    #check_unique_elements()
    
    #get the secret key d (bit vector representation of d)
    secret_key = build_matrix_solve_for_d()
    print("secret_key: ", end="")
    print(secret_key)
    
    #convert bit vector to integer, and set the private key
    print(cr.set_new_private_key(convert_bit_sequence_to_int(secret_key)))
    
    #debugging purpose
    #print(cr.cloud_key)
    print(cr.get_flag())
    
if __name__ == "__main__":
    from public import carpet_pubkey
    from public import carpet_test_key, cloud_test_key

    PORT = 51031

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        #from this (and inspecting the client and server side code), I infer that key = carpet_pubkey is used to verify the signatures I receive from the server (public key) - the server has the corresponding private key (in server code, it's self.key, the private key used to sign messages that are sent to me)
        #which means that cloud_key is the key used to sign my own messages and the server has the corresponding public key. Problem is, I don't know that public key (because I don't know the secret key so I cannot derive the public key).
        key = carpet_pubkey
        cloud_key = None
        
        '''
        Here is the setting: I, with some identity, send a message (with some [probably] invalid signature). The server takes that identity, uses that identity's public key to check for validity of signature. So I, the client, can control, which identity is used and therefore control which public key by the server to check signature validity.
        There are two identities to use (see server code): carpet and carpet_cloud.
        
        What is also in the server code is that whatever the server signs, the (private) key (server code it's the key self.key [also called the carpet_test_key]) is used, which is associated with the identity carpet (this is  IMPORTANT  ). I, the client, happend to have the corresponing public key, so I can verify the signature.
            
        What the server has:
            The private key associated with identity carpet -> (hence it knows the corresponding public key as well)
            The private key associated with identity carpet_cloud -> (hence it knows the corresponding public key as well)
            
        What I , the client,  have:
            The public key associated with identity carpet
            
        What I do not have:
            I do not have the public key associated with identity carpet_cloud
            I do not have any secret keys corresponding to public keys of the server
            
        What I cannot do: 
            Send command queries with valid signatures, under identity carpet or carpet_cloud (don't have secret key)
            
        What I want to achieve:
            Send the flag command, with a valid signature, such that I get the flag.
            
        When interacting with the server, the only signed messages can only come from the server.
        Which means that the secret key, associated with identity carpet, is used, always.
        
        What we can do is query many commands, for which, because we don't have a valid signature on the commands we send to the server, receive error messages and the corresponding signatures, signed by key associated with identity carpet. Turns out, due to the cryptographically unsafe way to generate nonces, we can exploit these signatures and obtain the secret key assoicated with carpet. Then, because we can control which public key is used to verify on the server side, by specifying what identity I, the client, use, I can use the secret key; generate a valid signature on the flag command, which passes the signature validity check, and get the flag. (for how this is done, please see above)
        
        Note that I cannot do that under the identity carpet_cloud because I never receive nor can I generate any signatures with the secret key associated with this identity.
        '''

    else:
        HOSTNAME = "localhost"
        key = carpet_test_key
        cloud_key = cloud_test_key

    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, key, cloud_key)
