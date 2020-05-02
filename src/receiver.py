import socket
import hmac
import hashlib
from modes import Crypto


if __name__ == "__main__":
    
    HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
    PORT = 1234        # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            
            print('Connected by', addr)
            print("\nWaiting for config")
            config = conn.recv(1024)
            config = config.decode('cp437')
            if config:
                msg = 'Server received config successfully: ' + config
                conn.sendall(msg.encode('cp437'))
                
                print("Received Config " + config)
                mode, key, hkey, block_size, iv, ctr = config.split('||')
                crypto_obj = Crypto(mode=mode, key=key, block_size=int(block_size), IV=iv, ctr=ctr)

                while True:

                    # Receive Config        
                    print("\nWait for Message\n")
                    data = conn.recv(1024)
                    if not data:
                        break

                    # Recieve Encrypted Msg
                    data = data.decode('cp437')
                    cipher, rec_h = data.split('HMACAUC')
                    cipher = cipher.encode('cp437')

                    plain_msg = crypto_obj.decrypt(cipher)

                    h = hmac.new(hkey.encode('cp437'), plain_msg.encode('cp437'), hashlib.sha256)
                    if rec_h == h.hexdigest():
                        print("Correct MAC")
                        print("Received Cipher: ", repr(cipher))
                        print("Decrypted Msg: " + plain_msg)
                    else:
                        print("Wrong MAC, Message is invalid")
