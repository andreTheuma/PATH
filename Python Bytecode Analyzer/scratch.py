import hashlib
import dis
import os

def test():
    try:
        print("Hello")
    except Exception:
        print("This is an exception")

dis.dis(test)