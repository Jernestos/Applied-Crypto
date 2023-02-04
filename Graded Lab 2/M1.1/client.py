import json
from typing import Tuple
from telnetlib import Telnet

from Crypto.PublicKey.ElGamal import ElGamalKey

from public import ElGamalInterface
from Crypto.Util.number import *     #allowed
import random #allowed - part of standard library

from Crypto.PublicKey import ElGamal

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

#copy pasted from M1.0
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


def choose_my_own_key():
    #read in public avaiable parts of the public key
    from public import g as carpet_g #group order
    from public import test_g as carpet_test_g
    from public import p as carpet_p #group order
    from public import test_p as carpet_test_p
    
    p = g = h = None #public key parameters, not hard coded
    #I choose my own secret key and derive, using the available public key parts, the last part my public key, the y component.
    x = 42 #does not really matter what we choose as long as it complies with elgamal secret key constraints, it's my secret key anyway.
    if REMOTE:
        g = carpet_g
        p = carpet_p
    else:
        g = carpet_test_g
        p = carpet_test_p
    
    y = pow(g,x,p)
    return (x, p, g, y)

class CarpetRemote():
    def __init__(self, tn):
        """ Your initialization code goes here.
        """
        self.tn = tn
        self.x, self.p, self.g, self.y = choose_my_own_key()
        self.key = ElGamal.construct((self.p, self.g, self.y, self.x))
        
    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")

    def enc_json_recv(self):
        enc_res = self.json_recv()["enc_res"]
        res = ElGamalImpl.decrypt(self.key,
                bytes.fromhex(enc_res["c1"]),
                bytes.fromhex(enc_res["c2"]))
        return json.loads(res.decode())
        
    
    def get_error_msg(self):
        #this is merely a helper function used to deterine what kind of error message I get back.
        c1 = bytes([0]).hex() #this choice is important as this will trigger an exception that I know; see below
        c2 = bytes([42]).hex() #just some value
        
        
        #Taking a look at https://pycryptodome.readthedocs.io/en/latest/src/public_key/elgamal.html and wondering if there is an invalid value for c1 or c2, and working under the assumption that if there are such invalid values for ciphertexts, then this would yield a ValueError exception (or just some kind of exception) in the exec_command_secure method (serverside), triggering the except clause. I came up with 0 being an invalid value for c1, since, by the provided paper, c1 = g^y, for y being a uniform random element from Zp\{0}, g generator, c1 cannot be 0 because y cannot be p. Therefore, by triggering this exception with c1 = 0, I know exactly the underlying plaintext, which is "ElGamal: illegal c1 value: 0". So I know the underlying plaintext of the exception message.
        #note that when I tested this code against the remote server, I got the "ElGamal: illegal c1 value: 0", but when I tested this code against the local server, I got "Expecting value: line 1 column 1 (char 0)".
        #so to make it more general, instead of hardcoding the error in plaintext, I use this method, which returns the error in dictionary type format, independent if remote or local server is used.
        
        #form the overall ciphertext and send it to server
        #note that I specify my own public key here because I want to be able decrypt it.
        ciphertext = {"c1": c1, "c2": c2, "p": self.p, "g": self.g, "y": self.y}
        self.json_send(ciphertext)
        return self.enc_json_recv()
        
    def get_flag2(self):
        
        #get the error message (as dictionary)
        error_message_plaintext_dict = self.get_error_msg()
        
        #debugging
        #print(type(error_message_plaintext_dict))
        #print(error_message_plaintext_dict)
        
        #json + encode
        exception_message = json.dumps(error_message_plaintext_dict).encode()

        #convert to integer
        exception_message_long = bytes_to_long(exception_message)
        #take inverse
        exception_message_long_inv = inverse(exception_message_long, self.p)
        
        #make backdoor command
        backdoor_command = {
            "command": "backdoor"
        }
        #json + encode, and convert it to integer
        backdoor_command_long = bytes_to_long(json.dumps(backdoor_command).encode()) % self.p
        
        #now get the ciphertext corresponding to error_message_plaintext_dict
        #so similar as in get_error_msg, we query this.
        #note that this time, we do not specify the public key to use -> we want the server to use its public key for encryption.
        #why? because on server side, the decryption uses the key self.key, which we don't have (because we don't have the server's secret key). The encryption uses either the default key (self.key) (the public part) or the specified one we give to the server.
        #the goal is to inject the flag command into the ciphertext such that, when the server decrypt it with self.key (its private key), the ciphertext decrypts to the flag command and does not cause some error
        #side-note: we already know the underlying error plaintext: error_message_plaintext_dict
        #so if we specify here our own public key for the server to use, then because we know what happens due to what get_error_msg does, we cause an exception and land in the except branch, which then would encrrypt the error message with the public key specified. 
        #So what I aim for is: get a ciphertext that is the result of the encryption of a plaintext (which I know by get_error_msg because the same ciphertexts are queried) under the server's secret key [IMPORTANT] (due to exception landed in the except case now). This is good, because if we can somehow inject our flag command into the ciphertext (see below how that works and why), and send that modified ciphertext to the server, the modified ciphertext will decrypted under the server's secret key (based on server code). If this decryption + decoding happens without error, then we can invoke exec_command on the server, which gives us the flag and is excalty what we want.
        #in short: have the server encrypt and decrypt under its public key and the server's corresponding secret key
        #so now specifying own public keys here.
        ciphertext = {"c1": bytes([0]).hex(), "c2": bytes([42]).hex()}
        self.json_send(ciphertext)
        #this triggers an exception for which we know the underlying plaintext (because we used method get_error_msg before)
        #get ciphertext (the underlying plaintext is given by error_message_plaintext_dict) and split it into its components c1 and c2
        ciphertext_error = self.json_recv()
        c1 = ciphertext_error['enc_res']['c1']
        c2 = ciphertext_error['enc_res']['c2']
        
        #debugging
#        print("ciphertext_error: ", end="")
#        print(ciphertext_error)
#        print(c1)
#        print(c2)
        
        #inject flag command into ciphertext: why this works (mathematically) see huge comment at almost end of file.
        #modify c2 to c2_primed = c2 * exception_message_long_inv * backdoor_command_long
        #conversion into integer
        c2_as_integer = bytes_to_long(bytes.fromhex(c2)) % self.p
        
        #that's where the injection happens; exception_message_long_inv cancels out the underlying plaintext of c2_as_integer. What remans if some K times backdoor_command_long modulo p, where K comes from elgamal c2 computation: c2_as_integer = K * (underlying plaintext of c2_as_integer) mod p.
        c2_modified = (((c2_as_integer * exception_message_long_inv) % self.p) * backdoor_command_long) % self.p
        
        #this time around, I specify my public key for the server to use in the encryption, because I want to be able to decrypt and read the underlying plaintext.
        new_ciphertext_and_public_key = {
            "c1": c1,
            "c2": long_to_bytes(c2_modified).hex(),
            "p": self.p,
            "g": self.g,
            "y": self.y
        }
        
        self.json_send(new_ciphertext_and_public_key)
        return self.enc_json_recv()

'''
Analysis.

Observe that in the main method, on the server-side, whatever I, the client, sent to the server the following methods will be invoked: 
    msg = self.read_message()
    res = self.exec_command_secure(msg)
    self.send_response(res)
    
read_message is to parse the sent message
exec_command_secure is what we are going to exploit and with send_response we are going to receive the information.

Observe that in each message we sent to the server, method exec_command_secure is invoked. We can either fully specify the public key , or if not done fully, the server uses the default key, which we don't know.



Observe: In server.py, in method "exec_command_secure", I can get the flag by passing the appropriate encrypted command (which I don't know but can figure out - see below). In fact, this is the only place where is this possible. I place in this method after every line a print statement to track how far my ciphertexts made it through and additionally check what kind of exception it throws, if any. #only server code, for me locally to debug

Idea rough sketch - details above in code:
Note that Elgamal is malleable: given ciphertext (c1,c2) (for unknown plaintext m), (c1, c' * c2) is the encryption of plaintext c' * m [mod p]. We can exploit in the following way: After we sent ciphertext_to_send, we get the encryption (ElGamal) of the exception as response, call it (c1, c2). Let server secret key be x, and h_default := g^x mod p, and let y a uniform random element from Zp \ {0}, chosen by server. We have c2 = exception_msg * h^y. Then by malleability, (exception_msg)^(-1) * c2 = [(exception_msg)^(-1)] * (exception_msg * h^y) = 1 * h^y mod p. So we can inject our backdoor command (in code called "backdoor_command") into c2 the following way, exploiting what we have just figured out. c2' := (backdoor command string) * (exception_msg)^(-1) * c2 = (backdoor command string) * [(exception_msg)^(-1)] * (exception_msg * h^y) = (backdoor command string) * 1 * h^y = (backdoor command string) * h^y mod p. 

So if we send back the ciphertext (c1, c2') to the server, the server decrypt it to (backdoor command string), which instructs the server to get the flag and then encrypt it and set it back to me. Now I have to decrypt it to get the flag. If the server encrypt it using it's default public key (which I don't know fully), then I have no chance to learn the flag since I don't know the secret key x. But I am given the option to specify my public key, hence I can generate my own secret key, derive the public key fully (custom method choose_my_own_key does that without hardcoding the public keys), and sent it along with (c1, c2'). Then the server uses my public key to encrypt the flag and I can decrypt it, while it uses its secret key to decrypt (c1, c2'). (more details above)

'''

def interact(tn: Telnet, carpet_key_p):
    """ Your attack code goes here.
    """
    #see above for details and explaination
    cr = CarpetRemote(tn)
    print(42 * "-")
    print(cr.get_flag2())
    print(42 * "-")


    
    #not needed - not even implemented
    #print(cr.get_status())

if __name__ == "__main__":
    from public import p as carpet_p
    from public import test_p as carpet_test_p

    PORT = 51011

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        p = carpet_p

    else:
        HOSTNAME = "localhost"
        p = carpet_test_p


    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, p)
