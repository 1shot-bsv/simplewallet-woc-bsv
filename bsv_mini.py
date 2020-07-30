import secrets
import ecdsa
import hashlib
#import base58
from crypto import b58encode,b58decode_check,b58encode_check,bytes_to_wif,public_key_to_address


maxval='fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
maxval_int=int(maxval,16)-1
class bsv():
    def __init__(self,wif=None):
        if wif==None:
            self.PrivateKey = self.new_privkey()
            self.public_key = self.to_public_key_compressed()
            self.address = self.to_address()
        else: 
            extended_privatekey = b58decode_check(wif)
            if extended_privatekey[:1] != b'\x80':
                print('not mainnet key')
            elif extended_privatekey[-1:] != b'\x01':
                print('not compressed key')
            else:
                self.PrivateKey = ecdsa.SigningKey.from_string(extended_privatekey[1:][:-1], curve=ecdsa.SECP256k1)
                self.public_key = self.to_public_key_compressed()
                self.address = self.to_address()
    def __repr__(self):
        return "<PrivateKey: "+self.address + ">"
    
    def new_privkey(self):
        pk_num = secrets.randbelow(maxval_int)+1
        pk_hex = format(pk_num, '064x')
        PrivateKey=ecdsa.SigningKey.from_string(bytes.fromhex(pk_hex), curve=ecdsa.SECP256k1)
        return PrivateKey

    def to_public_key_compressed(self):
        if self.PrivateKey.privkey.public_key.point.y()%2==0:
            return '02'+format(self.PrivateKey.privkey.public_key.point.x(),'064x')
        else:
            return '03'+format(self.PrivateKey.privkey.public_key.point.x(),'064x')

    def to_address(self):
        address = public_key_to_address(bytes.fromhex(self.public_key))
        return address
    
    def to_hex(self):
        return self.PrivateKey.to_string().hex()
    
    def to_wif(self):
        wif = bytes_to_wif(self.PrivateKey.to_string(),prefix='main', compressed=True)
        return wif
    
    def from_hex(self,hex_string = None):
        if hex_string!=None:
            wif = bytes_to_wif(bytes.fromhex(hex_string),prefix='main', compressed=True)
            return bsv(wif=wif)
    
    def sign(self,msg):
        return self.PrivateKey.sign_deterministic(msg,hashfunc=hashlib.sha256,sigencode=ecdsa.util.sigencode_der_canonize)
    
    



