import hashlib
import dis
import os

def md5():
    new_str = str(54)
    
    print(hashlib.md5(new_str.encode()))
    #print (hashlib.md5(b'hi')  hashlib.md5(new_str.encode()))

#md5()

def funcF(x):
    
    def funcInc():
        # declaration of a nonlocal variable
        nonlocal x
        # increment x -> BINARY_ADD TOS = TOS1 & TOS.
        x += 1

    class X:
        def h(self):
            return x

    return X

print ((os.getcwd()))
print (os.path.dirname(os.getcwd()))

