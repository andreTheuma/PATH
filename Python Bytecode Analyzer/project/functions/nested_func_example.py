import dis
class nested_func:
        
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

dis.dis(nested_func.funcF)