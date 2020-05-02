from des import DesKey

def byte_xor(s1, s2):
    """xor two encoded string and return the result in binary"""

    return bytes(_a ^ _b for _a, _b in zip(s1, s2))

class Crypto():

    def __init__(
        self,
        mode = "ECB",
        key = "some key",
        block_size = 8,
        IV = "TWOBUCKS",
        s = 5,
        ctr = "7"
        ):
        
        self.mode = mode
        self.key = key
        self.block_size = block_size
        self.IV = IV
        self.ctr = ctr
        self.s = s
        
        self.encoding = 'cp437'
        self.key_obj = DesKey(self.key.encode(self.encoding))
        self.IV = self.IV.ljust(len(self.IV)+self.block_size\
            - (len(self.IV)+self.block_size)%self.block_size, 'X') if len(self.IV)%self.block_size else self.IV
        self.ctr = self.ctr.zfill(self.block_size)

    def encrypt(self, plain_text):

        plain_text = plain_text.ljust(len(plain_text)+self.block_size\
            - (len(plain_text)+self.block_size)%self.block_size, ' ')
        
        return eval(f'self.encrypt_{self.mode}')(plain_text)

    def decrypt(self, cipher_text):

        return eval(f'self.decrypt_{self.mode}')(cipher_text).rstrip()

    def encrypt_ECB(self, plain_text):
        """plain_text: input plain text in string format"""
        
        cipher_text = ""
        for i in range(0, len(plain_text), self.block_size):

            plain_block = plain_text[i:i+self.block_size]
            cipher = self.key_obj.encrypt(plain_block.encode(self.encoding))
            cipher_text += cipher.decode(self.encoding)

        return cipher_text.encode(self.encoding)
    
    def decrypt_ECB(self, cipher_text):
        """cipher_text: input cipher text in binary"""
        
        plain_text = ""     
        for i in range(0, len(cipher_text), self.block_size):

            cipher_block = cipher_text[i:i+self.block_size]
            plain = self.key_obj.decrypt(cipher_block)
            plain_text += plain.decode(self.encoding)

        return plain_text
            
    def encrypt_CBC(self, plain_text):

        iv = self.IV.encode(self.encoding)
        cipher_text = ""
        for i in range(0, len(plain_text), self.block_size):

            plain_block = plain_text[i:i+self.block_size]
            xor_plain = byte_xor(plain_block.encode(self.encoding), iv)
            cipher = self.key_obj.encrypt(xor_plain)
            cipher_text += cipher.decode(self.encoding)
            iv = cipher

        return cipher_text.encode(self.encoding)

    def decrypt_CBC(self, cipher_text):

        iv = self.IV.encode(self.encoding)
        plain_text = ""
        for i in range(0, len(cipher_text), self.block_size):
            
            cipher_block = cipher_text[i:i+self.block_size]
            plain_block = self.key_obj.decrypt(cipher_block)
            plain_block = byte_xor(plain_block, iv)
            plain_text += plain_block.decode(self.encoding)
            iv = cipher_block

        return plain_text

    def encrypt_CFB(self, plain_text):

        iv = self.IV.encode(self.encoding)
        cipher_text = ""
        for i in range(0, len(plain_text), self.s):

            plain_block = plain_text[i:i+self.s]
            cipher_block = self.key_obj.encrypt(iv)
            cipher_block = byte_xor(cipher_block[:self.s], plain_block.encode(self.encoding))
            cipher_text += cipher_block.decode(self.encoding)
            iv = iv[self.s:] + cipher_block
        
        return cipher_text.encode(self.encoding)

    def decrypt_CFB(self, cipher_text):

        iv = self.IV.encode(self.encoding)
        plain_text = ""
        for i in range(0, len(cipher_text), self.s):
            
            cipher_block = cipher_text[i:i+self.s]
            plain_block = self.key_obj.encrypt(iv)
            plain_block = byte_xor(plain_block[:self.s], cipher_block)
            plain_text += plain_block.decode(self.encoding)
            iv = iv[self.s:] + cipher_block

        return plain_text

    def encrypt_CTR(self, plain_text):

        cipher_text = ""
        ctr = self.ctr.encode(self.encoding)
        for i in range(0, len(plain_text), self.block_size):

            plain_block = plain_text[i:i+self.block_size]
            cipher_block = self.key_obj.encrypt(ctr)
            cipher_block = byte_xor(cipher_block, plain_block.encode(self.encoding))
            cipher_text += cipher_block.decode(self.encoding)
            ctr = (str(int(ctr.decode(self.encoding)) + 1).zfill(self.block_size)).encode(self.encoding)

        return cipher_text.encode(self.encoding)

    def decrypt_CTR(self, cipher_text):

        plain_text = ""
        ctr = self.ctr.encode(self.encoding)
        for i in range(0, len(cipher_text), self.block_size):
        
            cipher_block = cipher_text[i:i+self.block_size]
            plain_block = self.key_obj.encrypt(ctr)
            plain_block = byte_xor(cipher_block, plain_block)
            plain_text += plain_block.decode(self.encoding)
            ctr = (str(int(ctr.decode(self.encoding)) + 1).zfill(self.block_size)).encode(self.encoding)

        return plain_text
        

if __name__ == "__main__":

    x = "some key"
    key0 = DesKey(x.encode('cp437'))

    tst = 'some pen in my pocket SO what should i do'
    tst2 = 'er'

    s = "HI"
    s = s.zfill(1)
    obj = Crypto(mode="CTR", key=x, block_size=16)
    breakpoint()
    enc = obj.encrypt(tst)
    dec = obj.decrypt(enc)
    
    print(dec)
