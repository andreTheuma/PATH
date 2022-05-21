import code
from inspect import getmembers,isfunction

from functions import test_simple_module as function

#function_list = getmembers(test_simple_module, isfunction)

code_object = function.main.__code__
print(code_object)
##for functions in function_list:




