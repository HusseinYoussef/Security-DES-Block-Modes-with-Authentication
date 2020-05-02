import socket
import hmac
import hashlib
from modes import Crypto

if __name__ == "__main__":

    HOST = '127.0.0.1'  # The server's hostname or IP address
    PORT = 1234        # The port used by the server
     
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        mode = "ECB"
        key = "some key"
        hkey = "SECURITY"
        iv = "TWOBUCKS"
        ctr = "4"
        block_size = "8"

        print("Press 1 to skip this and proceed with the default configurations or press any other key to use your own configurations.")
        
        inp = input()
        val = 0
        try:
            val = int(inp)
        except:
            val = 0
        
        if val != 1:
            print("Now Enter the configurations\n")
            print("\nEnter the mode: ECB, CBC, CFB, CTR")
            inp = input()
            if inp.upper() == 'ECB':
                mode = 'ECB'
            elif inp.upper() == 'CBC':
                mode = 'CBC'
            elif inp.upper() == 'CFB':
                mode = 'CFB'
            elif inp.upper() == 'CTR':
                mode = 'CTR'
            else:
                print("Invalid mode the default will be chosen")
            print("Mode: " + mode)

            print("\nEnter Encryption Key, it should be of length 8")
            inp = input()
            if len(inp) != 8:
                print("Invalid Key the default will be chosen")
            else:
                key = inp
            print("Key: " + key)

            print("\nEnter Hashing Key")
            inp = input()
            if len(inp) == 0:
                print("Invalid Key the default will be chosen")
            else:
                hkey = inp
            print("Hash Key: " + hkey)

            print("\nEnter Block Size, it should be divisible by 8")
            inp = input()
            try:
                b_size = int(inp)
                if b_size % 8 != 0:
                    print("Invalid block size the default will be chosen")
                else:
                    block_size = str(b_size)
            except:
                    print("Invalid block size the default will be chosen")
            finally:
                    print("Block Size: " + block_size)

            print("\nEnter Initialization Vector IV")
            inp = input()
            if len(inp) == 0:
                print("Invalid Key the default will be chosen")
            else:
                iv = inp
            print("IV: " + iv)
            
            print("\nEnter the initial value of counter")
            inp = input()
            try:
                val = int(inp)
                ctr = str(val)
            except:
                print("Invalid value, the default will be chosen")
            finally:
                print("Counter: " + ctr)


        crypto_obj = Crypto(mode=mode, key=key, block_size=int(block_size), IV=iv, ctr=ctr)
        
        # Send config
        s.sendall(mode.encode('cp437')
					+ '||'.encode('cp437')
					+ key.encode('cp437')
					+ '||'.encode('cp437')
                    + hkey.encode('cp437')
					+ '||'.encode('cp437')
					+ str(block_size).encode('cp437')
					+ '||'.encode('cp437')
					+ iv.encode('cp437')
					+ '||'.encode('cp437')
					+ ctr.encode('cp437')
				)
        data = s.recv(1024)
        print('\nReceived', (data))

        # Send Message
        while True:
            print("\nEnter the message you want to send") 
            msg = input()
            cipher = crypto_obj.encrypt(msg)

            print("Plain Text: " + msg)
            print("Cipher Text: ", repr(cipher))

            h = hmac.new(hkey.encode('cp437'), msg.encode('cp437'), hashlib.sha256)
            s.sendall(cipher + 'HMACAUC'.encode('cp437') + h.hexdigest().encode('cp437'))
        