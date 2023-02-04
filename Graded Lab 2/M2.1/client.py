import json
from typing import Tuple, Optional
from telnetlib import Telnet

from Crypto.PublicKey.ECC import EccKey, EccPoint

from Crypto.PublicKey.ECC import EccKey, EccPoint
from Crypto.PublicKey import ECC

#import numpy as np
import math

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import *
from Crypto.Hash import SHA256

from Crypto.Util.strxor import *

from public import ECCInterface

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

"""
This is the client code that you should use for M2.1

Build upon the client code for M2.0 (copy pasted EECImlp code from M2.0) and find a way to obtain the flag from the server.
"""


'''
From https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html?highlight=EccKey
Preliminaries:
EccPoint:
    x (integer) – The affine X-coordinate of the ECC point
    y (integer) – The affine Y-coordinate of the ECC point
    xy – The tuple with X- and Y- coordinates
    ----
    diverse methods
    
EccKey:
    curve (string) – The name of the ECC as defined in Table 1.
    pointQ (EccPoint) – an ECC point representating the public component
    d (integer) – A scalar representating the private component
    ----
    diverse methods
    

    
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
Copy pasted task description - has no other purpose than having the info right here.
You are given the server code (server.py) running on each Carpet. The server offers a client interface to execute some commands on the Carpet.

Each server has a static (public, secret) keypair, and accepts commands encrypted under its public key using a hybrid encryption scheme. The first step is to give the carpet your public key. Then, you can issue encrypted commands to the carpet.

In order to decrypt the responses and issue encrypted commands, you must derive a symmetric key, using static ECDH. You will then use the symmetric keys to encrypt/decrypt using AES-GCM.

The commands will be interpreted and will produce a response (or an error message). The responses (resp. error messages) will be encrypted (again, using the hybrid encryption scheme) using the key that you previously provided to the server.

The comments in the client code will guide you through the implementation.

You will find the public key of the Carpet in public.py. You can assume that the public module will be present at writeup evaluation time.

'''


'''
NIST P-256 parameters
'''

a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

#some basic math stuff to compute log to base 256
def log256(value):
    return math.ceil(math.log(value) / math.log(256))

def i2osp(s: int, k: int) -> bytes:
    #https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
    #assume there is no error encountered, that is s is not too large.
    S = long_to_bytes(s)
    to_pad_length = len(S) - k
    if to_pad_length > 0:
        S = S + bytes([0]) * to_pad_length
    return S

#copy pasted from M2.0
class ECCImpl(ECCInterface):
    @staticmethod
    def ecc_point_to_bytes(point: EccPoint):
        """Compute the byte-representation of an elliptic curve point

        To compute a representation, we use the 1363-2000 IEEE Standard (Specifications for Public Key Cryptography). You can find the PDF here (use your ETH credentials):

        https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=891000
        
        
        
        This function should implement the EC2OSP specification. Mind that we are using *uncompressed* points for our purposes.
        
        EC2OSP:
        On page 214, E2.3.2:
            
        PO = PC | X | Y
        
        PC of the form 00000UCY_
        PC = 00000100, since uncompressed point -> U = 1, C = Y_ = 0
        
        Following is an excerpt from the paper: (Just to have the info here, with some comments form my side)
        X is the octet string of length log256 q representing xP according to FE2OSP (see 5.5.4).
        Y is the octet string of length log256 q representing yP of P according to FE2OSP (see 5.5.4) if the
        format is uncompressed or hybrid; -> That's what I need
        
        Y is an empty string if the format is compressed.
        
        Page 16, 5.5.4
        An element x of a finite field GF (q), for purposes of this standard, is represented by an integer if q is an odd
        prime (see 5.3.1) (by inspection of the value q in hex, q is an odd prime and not a power of two -> use this case)
        
        or by a bit string if q is a power of two (see 5.3.2).  (no, this does not apply here)
        
        If q is an odd prime, then to represent x
        as an octet string, I2OSP shall be used with the integer value of x and the length log256 q as inputs. (yes, applies, hence has to this conversion)
        
        If q is a power of two, then to represent x as an octet string, BS2OSP shall be applied to the bit string representing x [...]. (no, this does not apply here)
        
        Note that q is indeed an odd prime and not a power of 2, as easily seen by the hex-decimal representatino of q.
        So we encode x and y points as log256 q bytes via i2osp (since we are talking about uncompressed points, we apply this to y as well)
        
        
        """
        
        '''
        Idea: Follow recipe as outlined here and in paper.
        '''
        #Extract coordinates of points from ECCPoint point
        x = point.x 
        y = point.y
        
        #build PC
        PC = bytes([4])
        
        length = log256(q)
        X = long_to_bytes(x, length) #this is equivalent to i2osp(x, length); use cryptodomes functions instead of custom one; does not really matter - yields the same results. 
        Y = long_to_bytes(y, length) #i2osp(y, length)
        
        #build PO
        PO = PC + X + Y
        return PO

        #raise NotImplementedError

    @classmethod
    def derive_symmetric_keys(
        cls, privkey: EccKey, pubkey: EccKey
    ) -> Tuple[bytes, bytes]:
        
        """Derive an encryption key and a decryption key from a private EccKey and a public EccKey

        This method effectively implements the Elliptic Curve Diffie-Hellman key exchange.
        Given the 
        client's private key 
        and the 
        server's public key, 
        derive a shared point on the elliptic curve.

        Then, to derive one of the keys, compute:
            1. The byte representation of the shared point
            2. The byte representation of the pubkey of the receiver
            3. The byte representation of the pubkey of the sender
        using the `ecc_point_to_bytes` function above.

        Then, concatenate these three byte strings in the same order as above. Finally, hash the result with SHA-256. This will leave you with a 32-Byte AES-GCM key.

        For the encryption key, the sender will be the Client and the receiver will be the Server. For the decryption key, it will be the other way around. This yields two AES-GCM keys in total.

        Args:
            privkey (EccKey): the private key of the client
            pubkey (EccKey): the public key of the server

        Returns:
            (bytes, bytes): respectively, the AES-GCM encryption key and the AES-GCM decryption key
        """  
        
        '''
        Setting:
            
            ECDH - sketch for orientation
            Server = Alice
            Client = Bob
            
            Alice: pk = P, G, sk = a
            Bob:   pk = P, G  sk = b
            
            (1)
            Alice: x = aG mod P; send x to Bob
            Bob:   y = bG mod P; send y to Alice
            
            (2) 
            Alice: k = ay mod P
            Bob:   k = bx mod P
            
            We know the servers public key (carpet_pubkey), so the first computation (1) for Alice is already done by the server (an we have the result). So to compute the shared point (on client side), we just proceed with (2) in Bob's role, since Bob is the client and has alreay Alice's x.
        '''
        
        #shared point computation
        #extract the secret key d from privkey
        d = int(privkey.d)
        
        #extract the public key (x and y coordinates from point Q) from pubkey
        Q = pubkey.pointQ
        
        #compute shared key
        #make use of ECCPoint scalar multiplication
        shared_point = Q * d
        
        #compute byte representation of shared point
        byte_resp_of_shared_point = ECCImpl.ecc_point_to_bytes(shared_point)
        
        #compute byte representation of receiver's pubkey (Server)
        byte_resp_of_receiver_pb_key = ECCImpl.ecc_point_to_bytes(pubkey.pointQ)
        
        #compute byte representation of sender's pubkey (Client)
        sender_public_key = privkey.public_key() #generate the public key correspoding to the private key
        byte_resp_of_sender_pb_key = ECCImpl.ecc_point_to_bytes(sender_public_key.pointQ)
        
        #concatenate byte strings as described above in your instructions
        '''
        Then, to derive one of the keys, compute:
            1. The byte representation of the shared point
            2. The byte representation of the pubkey of the receiver
            3. The byte representation of the pubkey of the sender
        using the `ecc_point_to_bytes` function above.
        
        For the encryption key, the sender will be the Client and the receiver will be the Server. For the decryption key, it will be the other way around. This yields two AES-GCM keys in total.
        '''
        enc_key_bytes = byte_resp_of_shared_point + byte_resp_of_receiver_pb_key + byte_resp_of_sender_pb_key #because, I the client, send data, that I encrypt and the server, the recipient, decrypt
        
        dec_key_bytes = byte_resp_of_shared_point + byte_resp_of_sender_pb_key + byte_resp_of_receiver_pb_key #because the server, the sender, encrypts the data that I receive and decrypt.
        
        #hash results
        #h = SHA256.new()
        #h.update(enc_key_bytes)
        
        enc_key = SHA256.new(enc_key_bytes).digest() #bytes.fromhex(h.hexdigest())
        
        #h.update(dec_key_bytes)
        dec_key = SHA256.new(dec_key_bytes).digest() #hash value produced by command on the right is wrong (tested): bytes.fromhex(h.hexdigest())
        
        return (enc_key, dec_key)
        #raise NotImplementedError

    @classmethod
    def encrypt(
        cls, key_enc: bytes, message: bytes, nonce: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Your encryption code goes here.

        Use AES-GCM to encrypt `message` under `key_enc`. If the nonce is provided, you should use it. Otherwise, generate a random one. You should not include any Additional Data.

        Args:
            key_enc (bytes): The AES-GCM key to use for the encryption
            msg (bytes): the plaintext message to be sent
            nonce (Optional[bytes]): the nonce to be used for AES-GCM, if provided

        Returns:
            ciphertext (bytes): the AES-GCM encrypted ciphertext
            tag (bytes): the AES-GCM MAC tag
            nonce (bytes): the AES-GCM nonce
        """
        #check if nonce given, if not, generate a random 16 byte nonce.
        if nonce is None:
            nonce = get_random_bytes(16)
        
        #aes encryption of plaintext message with key_enc, AES.MODE_GCM mode, and nonce
        aes_cipher = AES.new(key_enc, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = aes_cipher.encrypt_and_digest(message)
        
        return (ciphertext, tag, nonce)
        #raise NotImplementedError

    @classmethod
    def decrypt(
        cls, key_dec: bytes, ciphertext: bytes, tag: bytes, nonce: bytes
    ) -> bytes:
        """Your decryption code goes here.

        Use AES-GCM to decrypt `ciphertext` under `key_enc`, using the given `tag` and `nonce`.

        Args:
            key_dec (bytes): The AES-GCM key to use for the decryption
            ciphertext (bytes): the AES-GCM encrypted ciphertext to be decrypted
            tag (bytes): the AES-GCM tag for the MAC
            nonce (bytes): the AES-GCM nonce

        Returns:
            (bytes): the plaintext message
        """
        
        #eas descryption of ciphertext, using key_dec, AES.MODE_GCM and provided nonce
        aes_cipher = AES.new(key_dec, AES.MODE_GCM, nonce=nonce)
        plaintext = aes_cipher.decrypt(ciphertext)
        
        #check if MAC is valid
        try:
            aes_cipher.verify(tag)
            #print("Message is authentic.")
            return plaintext
        except ValueError:
            print("Message is not authentic and/or incorrect key.")
            return "Failure"
        #raise NotImplementedError


class CarpetRemote:
    def __init__(self, tn, carpet_key):
        """Your initialization code (if any) goes here."""
        self.tn = tn
        self.carpet_key = carpet_key #my public key

        #copy pasted from M2.0
        self.key: EccKey = ECC.construct(curve="NIST P-256", d=42) #my own private key
        self.key_enc , self.key_dec = ECCImpl.derive_symmetric_keys(self.key, self.carpet_key)
    
    #client (I) establish symmetric key pairs with servers
    def set_user_key(self):
        self.json_send(
            {
                "command": "set_user_key", #send my public key to the server
                "x": hex(self.key.pointQ.x)[2:],
                "y": hex(self.key.pointQ.y)[2:],
            }
        )
        res = self.json_recv()
        return res

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode("utf-8"))

    def json_send(self, req: dict):
        request = json.dumps(req).encode("utf-8")
        self.tn.write(request + b"\n")

    def enc_json_recv(self):
        enc_res = self.json_recv()["enc_res"]
        #print("enc_json_recv RECEIVED: ", end="")
        #print(enc_res)
        ciphertext = bytes.fromhex(enc_res["ciphertext"])
        tag = bytes.fromhex(enc_res["tag"])
        nonce = bytes.fromhex(enc_res["nonce"])

        res = ECCImpl.decrypt(self.key_dec, ciphertext, tag, nonce)
        #print("enc_json_recv RES: ", end="")
        #print(res)
        return json.loads(res.decode())

    def enc_json_send(self, req: dict):
        #print("enc_json_send START")
        request = json.dumps(req)
        ctxt, tag, nonce = ECCImpl.encrypt(self.key_enc, request.encode())
        #print("Encrypted command")
        #print("ciphertext: ", end="") 
        #print(ctxt.hex())
        #print("tag: ", end="")  
        #print(tag.hex())
        #print("nonce: ", end="")  
        #print(nonce.hex())
        obj = {
            "ciphertext": ctxt.hex(),
            "tag": tag.hex(),
            "nonce": nonce.hex(),
        }
        self.json_send(obj)
        
    def get_status(self):
        obj = {"command": "get_status"}
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res
     
    #get flag from cs
    def get_flag(self):
        obj = {"command": "send_flag_to_customer_service"}
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res
    
    #
    def get_cs_status(self):
        obj = {"command": "send_status_to_customer_service"}
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res
    
    def attack(self):
        
        '''
        Sketch:
        Observation: We have the following interaction:
        Client <----> Server <----> Customer Support. Whatever is communicated between Server and Customer Support, the client cannot decrypt it (because client does not know the decryption key). But client gets the encrypted messages, intended for customer support (server uses self,enc_key_cs for encryption), that is the underlying plaintext for customer support has been encrypted with enc_key_cs, such that only the customer support can decrypt it. The server (based on server code) happens to send us this encrypted message.
        '''
        print("INIT. ATTACK: ")
        '''
        Obserse: We are not using additional data. (https://fr.wikipedia.org/wiki/Galois/Counter_Mode -> So we are only using what's encircled in dashed line) We have a symmetric encryption that looks like counter mode, where AES acts as the block cipher. From the lectures we know that block ciphers are deterministic, hence same input -> same output.
        Idea: Observe that we are dealing with nonces and AES-GCM. From lecture we know that it's never good to reuse nonces (violates definition of nonce). We also know that AES is a block cipher and GCM is a mode, we talk about mode "counter mode". As seen by lecture, if we reuse nonces N to encrypt plaintext P and P' (with the same symmetric key), resulting in ciphertext C and C', then P xor P' = C xor C' (because of the way block ciphers work in counter mode, it cancels out the AES output via XOR). So if we know a bit about P (but not P'), we can solve for P' via P' = C xor C' xor P, that is we can learn about the bytes at the positions for which we know the correspoding bytes of P at the same position.
        
        Here: We know how the flag looks like: flag{....}, where we can only determine with certainty the first 5 bytes of it, namely "flag{", since I don't know the length of part in the curly brackets. Let's call "flag{" Pf.
            I also know, when sending/querying the command {"command": "send_status_to_customer_service"}, that the plaintext encrypted starts with "[Smart Carpet Dust Logging] User #1337 has sent a dust report to the customer service. Current dust level:", (because I have the server code). The remaining part cannot be determined due to variable length. Let's call this known plaintext as Pcs
            
            We can can xor the first 5 bytes of this message with "flag{", that is we compute P = Pf xor Pcs[:5].
            
            
            By querying / sending flag command {"command": "send_flag_to_customer_service"} we get the ciphertext of the flag. Let's call this ciphertext Cf. Recall: The underlying plaintext looks like flag{...}, where ... cannot be determined (random)
            
            By querying / sending status send_status_to_customer_service {"command": "send_status_to_customer_service"} we get the ciphertext of the "[Smart Carpet Dust Logging] User #1337 has sent a dust report to the customer service. Current dust level:...". Let's call the this ciphertext Ccs
            
            So we can also xor these two ciphertexts, yielding C = Cf xor Ccs (we assume that we can xor bytes sequences of different length here, for simplication of explaination, in code, this is also taken into account). Then we figure out if these two "xor-valued" are equal, that is if P == C[:5]. 
            
            If so, then it must mean that the same nonce was used for the two encryption of the plaintexts. (block ciphers are deterministic, AES is a block cipher)
                So we can now work backwards, from equation Cf xor Ccs = C = P = Pf xor Pcs[:5]. We don't now the full flag plaintext P, but we know that the euqation above must hold. So we can rearrange this equation to P = (Cf xor Ccs) xor Pcs to get the full plaintext. (we assume that we can xor bytes sequences of different length here, for simplication of explaination, in code, this is also taken into account).
                
            If not equal, then not the same nonce was used and we cannot exploit this as described above. So we query again the command send_status_to_customer_service for a new ciphertext, hoping that this time, the nonce, used for the flag, is chosen for the encryption here as well. 
            
            To turn this into an attack, we query / send send_status_to_customer_service command {"command": "send_status_to_customer_service"} multiple times, each time resulting in a different ciphertext (due to random choice of nonces), compute the xor of ciphertexts and check for equality as decribed above. The probability that we eventually get a ciphetext for which the nonce is the same as the flag-ciphertext is high enough, because ENTROPY_DIGITS is set to 2, so there are only 100 possible nonces possible (because in server code, we compute h = SHA256.new();
            h.update(entropy); nonce = h.digest()[:NONCE_SIZE] ; observe that h is for every nonce computation newly instatitated in the same manner, so for same entropy value we get the same nonce.)
        '''
        
        #get flag, that is encrypted under the encryption key self.enc_key_cs (see server code)
        flag_query_response = self.get_flag()
        #print("flag_query_response: ", end="")
        #print(flag_query_response)
        flag_ciphertext = bytes.fromhex(flag_query_response['res']['ciphertext']) #interested in ciphertext only
        
        flag_plaintext_known = "flag{".encode() #the flag begins with "flag{". So we know the first 5 bytes already of flag_ciphertext.
        
        cs_status_plaintext_known = "[Smart Carpet Dust Logging] User #1337 has sent a dust report to the customer service. Current dust level:".encode() #from server code, we know that this plaintext excerpt does not change; the only variable part is the random number between 1 and 10000, which we do not know about (nor the length since random), so everything after this variable part we cannot use.
        
        plaintext_xored_result = strxor(flag_plaintext_known, cs_status_plaintext_known[:5]) #we only know about the first 5 bytes of the flag message so we can only use the first 5 bytes of cs_status_plaintext_known.
        
        print("plaintext_xored_result: ", end="")
        print(plaintext_xored_result)
        
        print("START LOOP")
        #With good probability, Loop will end. (hint also says that)
        while True:
            print("Attempt: ", end="")
            
            #query customer support status, hoping that the same nonce was used as for the encryption of the flag.
            cs_status_query_response = self.get_cs_status()
            #print("cs_status_query_response: ", end="")
            #print(cs_status_query_response)
            #xtract ciphertext.
            cs_status_ciphertext = bytes.fromhex(cs_status_query_response['res']['ciphertext'])
            ciphertext_xored_result = strxor(cs_status_ciphertext[:5], flag_ciphertext[:5]) #we only know about the first 5 bytes of the flag message so we can only use the first 5 bytes of cs_status_plaintext_known.
            #print("ciphertext_xored_result: ", end="")
            print(ciphertext_xored_result)
            if plaintext_xored_result == ciphertext_xored_result:
                
                '''
                Explaination above
                '''
                #strxor required for xoring to byte sequences that they are of equal length, so we determine, of all three known; luckily, the min_length is at least as large the the flag plaintext.
                min_length = min(len(cs_status_plaintext_known), min(len(flag_ciphertext), len(cs_status_ciphertext)))
                
                #computing xor values according to equation above to recover the flag fully.
                ciphertext_xor = strxor(flag_ciphertext[:min_length], cs_status_ciphertext[:min_length])
                flag_plaintext = strxor(ciphertext_xor, cs_status_plaintext_known[:min_length])
                return flag_plaintext

def interact(tn: Telnet, carpet_key):
    """Your attack code goes here."""

    cr = CarpetRemote(tn, carpet_key)

    #first set key
    print(cr.set_user_key())
    print(cr.attack())



if __name__ == "__main__":
    PORT = 51021

    from public import carpet_pubkey, carpet_test_pubkey

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_pubkey #my public key
    else:
        HOSTNAME = "localhost"
        key = carpet_test_pubkey

    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, key)
