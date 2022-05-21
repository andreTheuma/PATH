import dis

def addition_parms(x,y):

    w=x+y
    t=2
    
    if w>2:
        return w
    
    t+=1
    
    if t>1:
        t+=2
    else:
        w+1
        t-1

    return w-1

def main():
    addition_parms(2,3)

if __name__ == "__main__":
    main()

dis.dis(addition_parms)