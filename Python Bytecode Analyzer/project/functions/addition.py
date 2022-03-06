from hashlib import new


def addition_numbers():
    tmp_int = 1
    tmp_int_2 = 3

    new_int  = tmp_int+tmp_int_2
    new_int_3 = new_int*new_int

    return new_int

import dis

dis.dis(addition_numbers)
