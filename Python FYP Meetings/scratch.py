import hashlib

def md5():
    new_str = str(54)
    
    print(hashlib.md5(new_str.encode()))
    #print (hashlib.md5(b'hi')  hashlib.md5(new_str.encode()))

md5()