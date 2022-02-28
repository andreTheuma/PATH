#!/usr/bin/env python
"""Generates facts from Python Function

Usage:
  test.py [--host=h] [--csv=c] [--skip=n] [--number=n] [--repeat-every=n]

Options:
  -h --help                         Show this screen.

    p -> print
    pp -> pretty print

"""
import code
from ctypes import sizeof
import os, sys
import docopt
import json
import csv
import dis, inspect, __future__
import pdb
import sys
import traceback
import hashlib

from sorting_handler import sorting_handler
from file_handler import file_handler
import functions.nested_func_example
import functions.primeNumberIntervals

import types

def init_function():
    nested_func = functions.nested_func_example
    prime_inter_func = functions.primeNumberIntervals
    return nested_func

#  .decl PushValue(stmt:Statement, v:Value)
#  .decl Statement_Opcode(statement: Statement, opcode: Opcode)
#  .decl Statement_Next(statement: Statement, statementNext: Statement)
#  .decl Statement_Pushes(statement: Statement, n: number)
#  .decl Statement_Pops(statement: Statement, n: number)
#  .decl Statement_Code(statement: Statement, )

def generate_statement_identifier(b, i):
    """
    Function to generate a unique statement ID.
    Args:
        b (bytecode): The disassembled bytecode object
        i (int): The index of the instruction

    Returns:
        long: An identifier
    """
    return hash(b) << 8 + i

def generate_statement_identifier_md5(b, i):
    """
    Function to generate an md5 unique ID.

    Args:
        b (bytecode): The disassembled bytecode object
        i (int): The index of the instruction

    Returns:
        md5: An identifier
    """

    #unique hash for bytecode
    bytecode_string = str(b)
    #bytecode_hash = hashlib.md5(bytecode_string.encode())

    index_string = str(i)
    #index_hash = hashlib.md5(index_string.encode())
    
    bytecode_index_string = bytecode_string+index_string
    md5_hash = hashlib.md5(bytecode_index_string.encode())

    return md5_hash

def get_pushes(i,push_val):
    """
    Function which returns the amount of pushes to the stack
    a bytecode call makes.

    Args:
        i (Instruction): is the bytecode instruction.
        push_val (int): are the amount of args pushed on the stack by the instruction

    Returns:
        dict[string, int]: Returns the Opname and its corresponding pushes to the stack

    """
    d = {'LOAD_FAST': 1,     #: 1
         'BINARY_ADD': push_val,
         'LOAD_CONST': 1,    #: 1
         'STORE_FAST': push_val,
         
         'MAKE_FUNCTION': push_val,
         'BUILD_TUPLE': push_val,
         'LOAD_DEREF': push_val,
         'INPLACE_ADD': push_val,
         'STORE_DEREF': push_val,
         'LOAD_CLOSURE': 1,
         'STORE_NAME': 0,
         'LOAD_BUILD_CLASS': push_val
         }
    if i.opname in d:
        return d[i.opname]
    return 0

def get_pops(i,pop_val):
    """
    Function which returns the amount of pops from the stack
    a bytecode call makes.

    Args:
        i (Instruction): is the bytecode instruction
        pop_val (int): are the amount of args popped on the stack by the instruction

    Returns:
        dict[string, int]: Returns the Opname and its corresponding pops from the stack

    """
    d = {'RETURN_VALUE': pop_val,
         'BINARY_ADD': pop_val,
         'BUILD_TUPLE': pop_val,
         'INPLACE_ADD': pop_val,
         'CALL_FUNCTION': pop_val
         }
    if i.opname in d:
        return d[i.opname]
    return 0

def main(function):

    ## TODO: FIX STATEMENT PUSHES AND POPS + IMPLEMENT STACK

    """
    Function which creates facts about a Python function for analysis. main makes use of recursive dissasembly

    Args:
        function (code object): This is the function code object which is passed through

    Returns:
        dict(set,set,set,set,set,set,set): A dictionary of sets corresponding to fact_dict
    """
    global inner_code_object_address_index

    push_value = set()
    statement_opcode = set()
    statement_next = set()
    statement_pushes = set()
    statement_pops = set()
    statement_code = set()
    statement_metadata = set()

    fact_dict = dict(
        
        PushValue=push_value,                   # set(Statement_ID: int, Value_Pushed_To_Stack: TOS)
        Statement_Pushes=statement_pushes,      # set(Statement_ID: int, Stack_Pushes:int)
        Statement_Pops=statement_pops,          # set(Statement_ID: int, Stack_Pops:int)
        Statement_Opcode=statement_opcode,      # set(Statement_ID: int, Statement_Opcode: Opcode)
        Statement_Code=statement_code,          # set(Statement_ID: int, Statement_CodeObject: code_object)
        Statement_Next=statement_next,          # set()
        Statement_Metadata=statement_metadata   # set(Statement_ID: int, Source_code_line_number: int, Bytecode_offset: int Original_Index: int )
    )

    bytecode = dis.Bytecode(function)
    prev_instruction = None

    line_number_table = line_number_table_generator(bytecode)

    for i, instruction in enumerate(bytecode):

        try:
            
            stack = inspect.stack()

            #frame = inspect.currentframe()

            arg_count = instruction.arg
            identifier = generate_statement_identifier_md5(bytecode, i)

            stack_size = bytecode.codeobj.co_stacksize
            live_locals = bytecode.codeobj.co_nlocals

            line_number = line_number_table[0][1]
            bytecode_offset = instruction.offset #line_number_table[l_count][0]

            """
            line_arg is in the format -> <line_number>.<bytecode_offset>
            BUG fix the bytecode offset implementation
            TODO add the amount of pushes & pops to stack
            TODO implement more opcodes
            """
            line_arg = line_number + bytecode_offset/100

            properties = identifier, instruction.argval #, line_arg
            #properties = identifier,line_arg

            statement_opcode.add((identifier, instruction.opname ))
            statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))
            statement_pops.add((identifier, get_pops(instruction,arg_count) ))
            statement_code.add((identifier, str(function) ))
            statement_metadata.add((identifier,line_arg))

            if prev_instruction:
                statement_next.add((identifier, generate_statement_identifier(prev_instruction, i - 1)))

            if instruction.opname == 'LOAD_CONST':
                push_value.add((properties))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'LOAD_FAST':
                push_value.add((properties))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'BINARY_ADD':
                push_value.add((properties))
                statement_pops.add((identifier, get_pops(instruction,arg_count) ))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'RETURN_VALUE':
                push_value.add((properties))
                statement_pops.add((identifier, get_pops(instruction,arg_count) ))

                continue

            if instruction.opname == 'STORE_FAST':
                push_value.add((properties))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'LOAD_CLOSURE':
                push_value.add((properties))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'MAKE_FUNCTION':
                push_value.add((properties))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                inner_code_object = list(bytecode)[i-2].argval
                inner_fact_dict = main(inner_code_object)
                for k, v in inner_fact_dict.items():
                    d = fact_dict[k]
                    d |= v

                continue

            if instruction.opname == 'BUILD_TUPLE':
                push_value.add((properties))
                statement_pops.add((identifier, get_pops(instruction,arg_count) ))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'LOAD_DEREF':
                push_value.add((properties))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'INPLACE_ADD':
                push_value.add((properties))
                statement_pops.add((identifier, get_pops(instruction,arg_count) ))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'STORE_DEREF':
                push_value.add((properties))
                #statement_pushes.add((identifier, get_pushes(instruction,arg_count) ))

                continue

            if instruction.opname == 'CALL_FUNCTION':
                push_value.add((properties))
                statement_pops.add((identifier, get_pops(instruction,arg_count) ))

                continue

            if instruction.opname == 'STORE_NAME':
                push_value.add((properties))
                #statement_pushes((identifier, 1))
                continue

            if instruction.opname == 'LOAD_BUILD_CLASS':
                push_value.add((properties))
                #statement_pushes((identifier, 1))
                continue
            
            if instruction.opname == 'LOAD_NAME':
                push_value.add((properties))
                #statement_pushes((identifier, 1))
                continue

        finally:
            prev_instruction = instruction

    return fact_dict

def init_sets():
    """
    Function which initializes all the sets
    """ 
    push_value = set()
    statement_opcode = set()
    statement_next = set()
    statement_pushes = set()
    statement_pops = set()
    statement_code = set()
    statement_metadata = set()
    
    return push_value,statement_opcode,statement_next,statement_pushes,statement_pops,statement_code, statement_metadata
 
def split_list(lst, size):
    """
    Function which splits a list

    Args:
        lst (hex[]): The list to be split up
        size (int): Chunks to split the list up in

    Yields:
        hex[]: Yields a number generator which corresponds to a byte
    """
    for i in range(0, len(lst), size):
        yield lst[i:i + size]

def line_number_table_generator(bytecode):
    """
    Function which handles the generation of the line number table

    Args:
        bytecode (code object): is the code object of the bytecode

    Returns:
        int[bytecode offset][line number]: An array correlating the bytecode offset with the sourcecode line number
    """
    
    line_number = bytecode.first_line

    line_number_table = []
    split_line_number_table = split_list(bytecode.codeobj.co_lnotab, 2)

    running_offset = 0
    running_line = line_number

    for j, byte in enumerate(split_line_number_table):
        offset = byte[0:1]
        line = byte[1:2]

        running_offset += ord(offset)
        running_line += ord(line)

        line_number_table.append(tuple((running_offset, running_line)))

    return line_number_table

if __name__ == '__main__':
    arguments = docopt.docopt(__doc__)
    try:
        
        function = init_function()
        
        dis.dis(function)
        
        code_object = function.nested_func.funcF.__code__

        out_obj = main(code_object)
        
        # init sorting handler
        sorter = sorting_handler()

        sorted_stmt_metadata = sorter.sort_metadata(out_obj)
        sorted_stmt_pushes = sorter.sort_stmt_pushes(out_obj)
        sorted_push = sorter.sort_push_values(out_obj)
        sorted_stmt_pops = sorter.sort_stmt_pops(out_obj)
        sorted_stmt_opcode = sorter.sort_stmt_opcodes(out_obj)
        sorted_stmt_code = sorter.sort_stmt_code(out_obj)

        # init file handler
        file = file_handler()

        file.save_to_csv(sorted_push, "PushValue")
        file.save_to_csv(sorted_stmt_metadata, "StatementMetadata")
        file.save_to_csv(sorted_stmt_pushes, "StatementPushes")
        file.save_to_csv(sorted_stmt_pops, "StatementPops")
        file.save_to_csv(sorted_stmt_opcode, "StatementOpcode")
        file.save_to_csv(sorted_stmt_code, "StatementCode")

        assert False

    except Exception:
        extype, value, tb = sys.exc_info()
        traceback.print_exc()
        pdb.post_mortem(tb)

'''
BYTECODE TERMS

TOS = top of stack

LOAD_FAST -> Pushes a reference to the local co_varnames[var_num] onto the stack.
LOAD_CONST -> Pushes co_consts[const i] onto the stack.
BINARY_ADD -> TOS = TOS1 & TOS.
RETURN_VALUE -> Returns with TOS to the caller of the function.

CALL_FUNCTION -> Calls a function. 
                The low byte of /argc/ indicates the number of positional parameters, the high byte the number of keyword parameters.
                On the stack, the opcode finds the keyword parameters first. 
                For each keyword argument, the value is on top of the key. 
                Below the keyword parameters, the positional parameters are on the stack, with the right-most parameter on top. 
                Below the parameters, the function object to call is on the stack.

LOAD_CLOSURE -> Pushes a reference to the cell contained in slot /i/
                of the cell and free variable storage.
                The name of the variable is co_cellvars[i] if i is less than the length of co_cellvars. 
                Otherwise it is co_freevars[i - len(co_cellvars)].
LOAD_METHOD -> 
BUILD_TUPLE -> Creates a tuple consuming /count/ items from the stack, 
                and pushes the resulting tuple onto the stack.
MAKE_FUNCTION -> Pushes a new function object on the stack. 
                TOS is the code associated with the function. 
                The function object is defined to have /argc/ default parameters, 
                which are found below TOS.
STORE_FAST -> Stores TOS into the local co_varnames

LOAD_BUILD_CLASS -> Pushes builtins.__build_class__() onto the stack. It is later called by CALL_FUNCTION to construct a class.

LOAD_DEREF -> Loads the cell contained in slot /i/ of the cell and free variable storage. 
                Pushes a reference to the object the cell contains on the stack.
INPLACE_ADD -> Implements in-place TOS = TOS1 + TOS (increment).
STORE_DEREF -> Stores TOS into the cell contained in slot /i/
                of the cell and free variable storage. (assignment)

http://unpyc.sourceforge.net/Opcodes.html
https://www.synopsys.com/blogs/software-security/understanding-python-bytecode/
https://ntnuopen.ntnu.no/ntnu-xmlui/bitstream/handle/11250/2515371/SimenBragen.pdf?sequence=1


'''
