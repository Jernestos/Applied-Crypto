import json
from typing import Tuple
from telnetlib import Telnet

from Crypto.PublicKey.ElGamal import ElGamalKey

from public import ElGamalInterface

from Crypto.Util.number import *     #allowed
import random #allowed - part of standard library

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

class ElGamalImpl(ElGamalInterface):
    '''
    Encryption and decryption methods based on the paper
    https://caislab.kaist.ac.kr/lecture/2010/spring/cs548/basic/B02.pdf

    Class methods used described here: 
    https://pycryptodome.readthedocs.io/en/latest/src/public_key/elgamal.html#Crypto.PublicKey.ElGamal.ElGamalKey

    '''
    
    '''
    The idea is to implement encryption/decryption as described in the paper linked above.
    We also need to determine which private key on client side is to be used. 
    Looking at the server code, we can see that if we do not provide a key, the server uses the default key, the carpet's key, namely carpet_test_key (from public.py), as public key. Because we know carpet_test_key, we can use it as well as our secret key (because it also includes the secret value) for decryption of messages that the server sent us. -> not giving any public key to the server when sending a command will cause the server to use the default public key, carpet_test_key, which is also used by the client (me), so both use the same keys for encryption/decryption.
    '''
    
    @classmethod
    def encrypt(cls, key, msg: bytes) -> Tuple[bytes, bytes]:
        
        #extract elements from key
        p = key.p
        g = key.g
        yb = key.y #note that y is the public key
        
        #idea: convert msg to an integer in order to perform exponantionen.
        m = bytes_to_long(msg) #int.from_bytes(msg, 'big') #python3.2+, native method, recommended by pycryptodome
        
        #choose k uniform at random between 0 and p - 1, inclusive borders 0 and p - 1
        k = random.randint(0, p - 1)
        
        K = pow(yb, k, p) #equation 1 in paper
        #then by equation 2, we compute the ciphertext
        c1 = pow(g, k, p)
        c2 = (K * m) % p
        
        #convert c1 and c2 into bytes, build tuple and output it.
        return (long_to_bytes(c1), long_to_bytes(c2))

    @classmethod
    def decrypt(cls, key, c1: bytes, c2: bytes) -> bytes:
        
        '''
        The paper also tells us how to decrypt. We implement this.
        '''
        
        #extract elements from key
        #need conversion to int to work.
        p = int(key.p)
        xb = int(key.x)
        
        #convert bytes to numbers:
        c1_n = bytes_to_long(c1)
        c2_n = bytes_to_long(c2)
        
        #first recover K, then the plaintext. It's stated in the paper how to do that.
        K = pow(c1_n, xb, p)
        
        #compute the inverse of K via Fermats little theorem.
        K_inv = pow(K, p - 2, p)
        
        plaintext_m_num = (K_inv * c2_n) % p
        
        #convert plaintext_m_num into bytes
        m = long_to_bytes(plaintext_m_num)
        
        return m

class CarpetRemote():
    def __init__(self, tn, carpet_key):
        """ Your initialization code (if any) goes here.
        """
        self.tn = tn
        #the public key of the server, with which I encrypt my command, so that the server can decrypt it.
        self.carpet_key = carpet_key
        self.key: ElGamalKey = carpet_test_key
        #by notification (from friday, around 15:00, at start of lab, allowing us to hardcode a key. This is the private key, and the server has the corresponding public key (if we do not sent our public key, it uses the default public key), so having the secret key, we can decrypt messages sent from the server to us. In fact, I know the default public key on server-side: carpet_test_key. Because this value is also known to me, I can use it as private key as well. (because we have the secret key included in carpet_test_key)

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")

    def enc_json_recv(self):
        enc_res = self.json_recv()["enc_res"]
        #observe that here, for decryption, self.key is used for decryption.
        #checking on server side code, if we do not give send the server our public key, the default public key carpet_test_key is used, but from public.py, we already the values of carpet_test_key
        res = ElGamalImpl.decrypt(self.key,
                bytes.fromhex(enc_res["c1"]),
                bytes.fromhex(enc_res["c2"]))
        return json.loads(res.decode())

    def enc_json_send(self, req: dict):
        request = json.dumps(req)
        #observe that self.carpet_key = carpet_key is used for encryption, the public key of the server
        c1, c2 = ElGamalImpl.encrypt(self.carpet_key, request.encode())
        #check what type the function is and what arguments are used for ElGamalImpl.encrypt
        #ElGamalImpl.encrypt(cls, key, msg: bytes) -> Tuple[bytes, bytes]:
        #key = carpet_key
        #msg = request.encode()
        obj = {
            "c1": c1.hex(),
            "c2": c2.hex(),
            "p": int(self.key.p),
            "g": int(self.key.g),
            "y": int(self.key.y)
        }
        self.json_send(obj)
    
    #similar structure as get_status, just juse the flag command 
    #do not give any public key, let the server default to its public key carpet_test_key, which we know fully.
    def get_flag(self):
        #flag command, not get_status command
        obj = {
            "command": "backdoor"
        }
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res
        
    def get_status(self):
        obj = {
            "command": "get_status"
        }
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res
        
'''
This is just a note to myself, understanding what "ElGamalKey" is.

For type "ElGamalKey" see here: https://pycryptodome.readthedocs.io/en/latest/src/public_key/elgamal.html#Crypto.PublicKey.ElGamal.ElGamalKey
ElGamalKey has
g generator
p modulus
y public key (g^x = y mod p)
x private key

has_private()
publickey()
'''

def interact(tn: Telnet, carpet_key: ElGamalKey):
    """ Your attack code goes here.
    """

    cr = CarpetRemote(tn, carpet_key)

    print(cr.get_flag())

if __name__ == "__main__":
    PORT = 51010

    from public import carpet_key, carpet_test_key

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_key
    else:
        HOSTNAME = "localhost"
        key = carpet_test_key

    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, key)
