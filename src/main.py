import hmac
import hashlib


if __name__ == "__main__":

    key = "HOMY"
    tst = "HELOO"
    h = hmac.new( key, tst, hashlib.sha256 )
    print( h.hexdigest() )