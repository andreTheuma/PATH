import dis


def addition_numbers(x,y):

    if x==1:
        x+=1
    else:
        x=y
        return
    z=x+y
    return z

#code = addition_numbers.__code__.co_code
#labels = dis.findlabels(code)
#print(labels)
#dis.dis(addition_numbers)
#for instruction in dis.get_instructions(addition_numbers):
#    print(instruction)
#    instruction.offset
