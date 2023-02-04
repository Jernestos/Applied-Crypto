import json
from telnetlib import Telnet

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import *

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

#from task description
#public key of the Carpet and the private key of the Carpet Cloud 

#int.from_bytes(bytes, 'big') : bytes -> big endian conversion; cryptodome says that; it also says that the eqivalent to that is bytes_to_long(bytes)

#some additional methods used to implement sign, encode and verify
def rsavp1(n, e, s):
  #assume no error occurs
  #so step 1 is okay
  
  #step 2
  m = pow(s, e, n)
  
  #step 3
  return m
  
def i2osp(s: int, k: int) -> bytes:
  #https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
  #assume there is no error encountered, that is s is not too large.
  S = long_to_bytes(s)
  to_pad_length = len(S) - k
  if to_pad_length > 0:
    S = S + bytes([0]) * to_pad_length
  return S
  
def rsasp1(K: RSA.RsaKey, m: int) -> int:
  #https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.1
  #Assume that K is a pair (n, d), since we don't have the other information to make a quintuple
  
  #setup - step 0
  n = K.n
  d = K.d
  
  #step 1, assume that m is in range between 0 and n - 1
  
  #step 2
  s = pow(m,d,n)
  #step 3
  return s

#encode re-checked
def encode(m: bytes, emLen: int) -> bytes:
    """ Custom EMSA-PKCS1-v1_5-style encoding.
    Follow the rfc8017 section 9.2, with the following exceptions:
    - always use SHA256 as the Hash,
    - discard step 2:
      - let T be (0x) 63 61 72 70 65 74 || H,
      - and tLen be the length in bytes of T.

    If you want to test your implementation against pycryptodome's pkcs1 v1.5 signatures,
    temporarily let T be (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
    Note: that "octet" = byte, "octet string" = bytes object

    Args:
        M (bytes): message to be encoded
        emLen (int): intended length in bytes of the encoded message, as per rfc8017

    Returns:
        EM: encoded message, a bytes object of length emLen
    """
    '''
    emLen    intended length in octets of the encoded message, at
              least tLen + 11, where tLen is the octet length of the
              Distinguished Encoding Rules (DER) encoding T of
              a certain value computed during the encoding operation
    '''
    #implementation idea: Follow the rfc8017 section 9.2, with the exception named above
        
    #setup - step 0
    hash256 = SHA256.new()
    T_values = b'\x63\x61\x72\x70\x65\x74'
    #T_values = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    #step 1
    
    hash256.update(m)
    H = bytes.fromhex(hash256.hexdigest())
    #step 2
    #omit by comment above
    
    #step 3
    T = T_values + H
    tlen = len(T)
    '''
    If emLen < tLen + 11, output "intended encoded message length too short" and stop.
    Let's assume this does not occur. Turns out this is not a problem when testing.
    '''
    
    #step 4
    length = emLen - tlen - 3
    PS = bytes([255]) * length
    '''
    The length of PS will be at least 8 octets.
    Let's assume this holds. Turns out this is not a problem when testing.
    '''
    #step 5
    EM = bytes([0]) + bytes([1]) + PS + bytes([0]) + T
    
    #step 6
    return EM
    #raise NotImplementedError

#re-check
def sign(K: RSA.RsaKey, M: bytes) -> bytes:
    """ Custom RSASSA-PKCS1-v1_5 (RSA Signature Scheme with Appendix)-style signature generation.
    Follow the rfc8017 section 8.2.1, with the following exception:
    - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.

    Args:
        K (RSA.RsaKey): signer's RSA private key.
        M (bytes): message to be signed.

    Returns:
        (bytes): encoded message, a bytes object of length emLen.
    """
    
    
    '''
    Idea: I just follow the instructions, given here.
    Follow the rfc8017 section 8.2.1, with the following exception:
    - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.
    '''
    
    #setup - step0
    k = len(long_to_bytes(K.n)) #checked
    #step 1
    EM = encode(M, k)
    '''
    If the encoding operation outputs "message too long", output
              "message too long" and stop.  If the encoding operation
              outputs "intended encoded message length too short", output
              "RSA modulus too short" and stop.
    Let's assume everything works fine. Turns out this is not a problem when testing.
    '''
    #step 2
    
    #step 2a
    '''
    Convert the encoded message EM to an integer message representative m = OS2IP (EM)
    '''
    m = bytes_to_long(EM) #this method is equivalent to the one on the right. int.from_bytes(EM, 'big') #OS2IP
    
    #step 2b
    '''
    Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA private key K and the message representative m to produce an integer signature representative s = RSASP1 (K, m).
    '''
    s = rsasp1(K, m) 
    #step 2c
    
    '''
    Convert the signature representative s to a signature S of length k octets (see Section 4.1): S = I2OSP (s, k).
    '''
    S = i2osp(s, k) #equivalent to long_to_bytes(s, k); see #https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#Crypto.Util.number.long_to_bytes; #S = i2osp(s, k)
    
    #step 3
    return S
    #raise NotImplementedError

#to check
def verify(N: int, e: int, M: bytes, S: bytes) -> bool:
    """ Custom RSASSA-PKCS1-v1_5 (RSA Signature Scheme with Appendix)-style signature verification.
    Follow the rfc8017 section 8.2.2, with the following exception:
    - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.

    Args:
        N, e: signer's RSA public key
        M (bytes): message whose signature is to be verified.
        S (bytes): signature to be verified, an bytes object of length k,
                   where k is the length in bytes of the RSA modulus n.

    Returns:
        (bool): True iif the signature is valid.
    """
    
    '''
    Idea: I just follow the instructions given here.
    Follow the rfc8017 section 8.2.2, with the following exception:
    - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.
    '''
    
    '''
    Assume errors do not occur, that is that in step 1 of rfc8017 section 8.2.2, valid inputs. Turns out this is not a problem when testing.
    '''
    
    #step 0 - setup
    k = len(long_to_bytes(N))
    
    #step 1 - assumed to be correct length
    
    #step 2
    
    #step 2a
    s = bytes_to_long(S) # this is equivalent to the methods used on the right: int.from_bytes(S, 'big') #OS2IP
    
    #step 2b
    m = rsavp1(N, e, s) #slight abuse of notation when compared to https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2; 
    
    #step 2c, assume no error occurs here; Turns out this is not a problem when testing.
    EM = long_to_bytes(m, k) #equivalent to i2osp(m, k)
    
    #step 3
    EM_primed = encode(M, k)
    
    #step 4
    #print(EM)
    #print(EM_primed)
    return EM == EM_primed
    
    #raise NotImplementedError

class CarpetRemote():
    def __init__(self, tn: Telnet, carpet_key: RSA.RsaKey, cloud_key: RSA.RsaKey):
        self.tn = tn
        self.carpet_key = carpet_key
        self.cloud_key = cloud_key

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")

    def json_signed_send(self, req: dict):
        signature = sign(self.cloud_key, json.dumps(req).encode())
        self.json_send({
            "identity": "carpet_cloud",
            "msg": req,
            "signature": signature.hex()
        })

    def json_signed_recv(self):
        res = self.json_recv()
        signature = bytes.fromhex(res["signature"])
        
        #print("json_signed_recv -> signature: ", end="")
        #print(signature)

        if "signed_res" in res:
            signed = json.dumps(res["signed_res"]).encode()
        else:
            signed = res["signed_error"].encode()

        if verify(self.carpet_key.n, self.carpet_key.e, signed, signature):
            print("Verification passed.")
            return signed
        return "VERIFY FAILED"

    def get_flag(self):
      #very similar to method "get_status" (difference is the command send to get the flag); if get_status works, then get_flag should also work
      obj = {
        "command": "backdoor"
      }
      self.json_signed_send(obj)
      res = self.json_signed_recv()
      return res
      
    def get_status(self):
        obj = {
            "command": "get_status"
        }
        self.json_signed_send(obj)
        res = self.json_signed_recv()
        return res

def testing(tn: Telnet):
  #for testing purposes; to check if the implementation is indeed correct
  #note that the values here are copy pasted from the test vector file.
    from test_vectors import skey
    
    in_1, out_1 = b'>', b'J\x05k\x8eM\x11\x99%8\xfa\xcd\xd5\xb6Mre\xb2]7\xe0\x08\xf9OBf\x14\xdd\xbb9\xa7\xc6p\xbb]\x93\xb3>C\xd4\xb4\xb4k\xafxX\x99\xb6\x8e\x10)\xda\xf4l\x1b\x922\x84\x9e\x85\x1dg"J\x84%\xedr/\xfd\xccs%\xb9\x15\xcc\xc6\x803mGh\x88m\xfd2\xadl\x0b*\xd1\xa5\x94\xb1\xa2b\xe8\xb9\x9eK\xe8v\xdd4nO|R\xe2\xf6lYLr\x15;\x021\xde\xc9\x87\xf6\xcd\x9c\xba\xd5c\x86^'
    in_10, out_10 = b'\x8b%\xe2!8\x9e\xb9\xb3z\xb6', b'5yk\x91`\xc8\x1d\x03>\x0e0\xa0;\x92\x16\xf1g\xde\x10<\xd7\x11\xf0\xa2H\xdf\x1aI\x1d[J\xa6?\xad\xd5\xa7\xaf\x0e\x02\xd6F\x9f\xf2\xc5\xa1\xab=\xf6\xfb\x98\x807\xcb\xe0ch\xa8\x1a\xce9\xfa*r\xa8Bk\rf\x8d\xc6\xe0\x0f\xe7\x12~\x99\x1bz&\xb5\xd5\xf9\xff\xb5\x87f\x8c\xf1\xae\xd6M"?\xed$\xbe\xb3\x83\x98\xe3^ue\xa8iY\xe07/\x07c\xea\x12\xb5\xa8\r\xd3\x8e\x9f?\x88\x81S\x05i\xec\x82\xa6'
    in_23, out_23 = b'\xe1\x1d\xb8?0\xeb\x15\xf2\xcc.\xcc!\xfd1\x91b\xfe\xfa\xdeav\t\xcb', b"\x1f\xcf\xcb\xbd\x11\x9eJ\xa9Re\x94\xd5>\xbdK\xad\xea\xeb\xf8'\x0f'\xe4n;u\xf2K3\xf7\x1c\xae\x12\xc9\x98\xad,\xf0\x06\x15s\xc8v\xf9U\x9c>D-x\x08\xee\xbd\xf3\xb1\x80s[\x90\x052\xae\xfc\xdd\xb9\x02c\xde;\x9f\x98?j\x81\xb7$zB\xab\x04\x0e\n\x8b<\xe6\x85\n\x8f\xc8A\r\xb5\x1b1\xaf\x0c\xcc\x0ft\xc2\x0e\x9e\x16\xd0\x8f\x8eP\x98J\x0c(&W\r%\xc3\x8d\xc1\x92\x9f\x9b\xd6\x04\xf1.\xed\x1df"
    in_32, out_32 = b'`\xd22\x9e\x0bE$yN\xb9\x03\x15\xe4IG\xbc\x10\x90\x06\xdee\xee\x8a\xe7\xfe4\x944\xd8\x8f\xee\xb9', b'\'\xc7t\xf7\x07\xa6\xa0\x8cv\xa2!\x1c\xff7\x95C\x9a(,\x9f\x1b\xbc\xc4%\xb4\x1f\xa4\xf4\xdcZ\xe8bHSh\xf6T\xbf\xc0\x06\xbf0p8\x90\x19k\xad\xb0\xab%\xc1\xd7[\x89\xb1\x8d\xcbz\x9c\xef\x92R[\xf8\x8b,j0sx\xfd.\x8c\xc3\x06Ws^\x81hg\xd9\xe3\x82\x8d\xf7\x1a\x9e\x00\xa6\x00\xd2\x02\xc3\xdb\xf5=\x1f\x97\xbe\x03\x1e]\x0ew"\x1d\x80hW\xbb\x86\xdc\xc8\x9ai,\xdbj\xa8\x81\xc2\xacr\r\x89\x0c'
    in_33, out_33 = b"\xbb\r\x87\xc7/\xc7`\xd2\xd7\nQ\xb75|\x83$\xecR\x8d08\xc3y\xeb\x9f\t':0\xa9\xca\xbb\x81", b'\x12\xf1\xaa\xb4O?\xe86\xe9\x1a\x18Aa\xd0\xd3\x86\x08\xdfd\xd3\xdce\xc7\xe4\x81i.\x83v,\xf7\xf2\x90\xce\xde\xfei7l\x11\xcaNh\x1a\xc4\x1c\x00\xe4$h\xae\xbc\x9f\xc5\x8b+\x9f\xa1\xf0\x97d\xd6LC/9\xa7\xd5\x94\xd5\xd0\x95\x1a\xc5\x12\xce\xfe\x01\x92\xf0\x97\x0cA\x86\xc3\xc2\x148&\xf94\x89\\\x0b\xcc{T\xc0z\x8f\xe5\x91A\x97]\xff\xfd\xdb\xb7\xe8\xfc {\xff\xbb\x88\x8d\xe3\xd7Pj\xef\xe3ZEXOu'
    
    inputs = [in_1, in_10, in_23, in_32, in_33]
    outputs = [out_1, out_10, out_23, out_32, out_33]
    
    for index in range(len(inputs)):
      cur_output = sign(skey, inputs[index])
      if cur_output != outputs[index]:
        print(str(index) + " does not match up: ")
      else:
        print(str(index) + " MATCH: ")
      print(cur_output)


def interact(tn: Telnet, carpet_key: RSA.RsaKey, carpet_cloud_key: RSA.RsaKey):
    """ Get the flag here.
    """
    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)
    #testing(tn) #used to check if sign is correct.
    #print(cr.get_status()) #not needed
    
    #this is used to get the flag.
    print(cr.get_flag())
  
if __name__ == "__main__":
    from public import carpet_pubkey, cloud_key
    from public import carpet_test_key, cloud_test_key

    PORT = 51040

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_pubkey
        cloud_key = cloud_key

    else:
        HOSTNAME = "localhost"
        key = carpet_test_key
        cloud_key = cloud_test_key

    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, key, cloud_key)
