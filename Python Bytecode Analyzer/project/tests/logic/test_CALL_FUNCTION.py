import dis

def addition(x,y):
    return x+y

def multiplication(x,y):
    return x*y

def main():
    w=addition(1,3)
    y=multiplication(w,2)

    z=y+w

    return z

if __name__ == "__main__":
    output = main()

dis.dis(main)