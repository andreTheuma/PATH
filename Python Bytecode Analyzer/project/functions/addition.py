from hashlib import new


def addition_numbers():
    new_int = 3
    test_var = 2
    test_string = "Hello"
    test_var+new_int

    if new_int > 3 :
        new_int=2
    else:
        s=2
    return new_int

import dis
code = addition_numbers.__code__.co_code
labels = dis.findlabels(code)
print(labels)
dis.dis(addition_numbers)
for instruction in dis.get_instructions(addition_numbers):
    print(instruction)
    instruction.offset