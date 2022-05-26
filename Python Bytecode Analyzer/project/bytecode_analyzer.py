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
from posixpath import sep
from threading import local
from tracemalloc import start
import docopt
import json
import csv
import dis, __future__
import pdb
import sys
import traceback
import hashlib
import time
from inspect import getmembers, isfunction

from sorting_handler import sorting_handler
from file_handler import file_handler
#import functions.primeNumberIntervals
#import functions.nested_func_example
#import functions.addition

from functions import addition as test_func
from tests.opcode import test_BINARY_SUBTRACTION as opcode_function
from tests.logic import test_BASIC_BLOCKS as logic_function
from tests.samplePrograms import P61_AddressBook as program_function
#from project import functions

import types

#def init_function(path):
    #TODO: add functionality to read path and create python object from path
#    nested_func = functions.nested_func_example
#    prime_inter_func = functions.primeNumberIntervals
#    add_func = functions.addition
#    add_func_with_parms = functions.addition_with_parms
    #function = 

#    return add_func_with_parms

#  .decl PushValue(stmt:Statement, v:Value)
#  .decl Statement_Opcode(statement: Statement, opcode: Opcode)
#  .decl Statement_Next(statement: Statement, statementNext: Statement)
#  .decl Statement_Pushes(statement: Statement, n: number)
#  .decl Statement_Pops(statement: Statement, n: number)
#  .decl Statement_Code(statement: Statement, )

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

    index_string = str(i)
    
    bytecode_index_string = bytecode_string+index_string
    md5_hash = hashlib.md5(bytecode_index_string.encode())
    hash_loc = md5_hash.hexdigest()

    return hash_loc

def generate_block_link_identifier_md5(prev_block_id, block_id):
    """
    #
    Function to generate an md5 unique ID.

    Args:
        prev_block_id(String): The previous block id
        block_id(String): The current block id

    Returns:
        md5: An identifier
    """

    #unique hash for bytecode
    prev_block_id_string = str(prev_block_id)
    block_id_string = str(block_id)
    
    block_link_string = prev_block_id_string+block_id_string
    md5_hash = hashlib.md5(block_link_string.encode())
    hash_loc = md5_hash.hexdigest()

    return hash_loc


def generate_variable_identifier_md5(v, i):
    """
    DEPRECATED
    Function to generate an md5 unique ID.

    Args:
        v (variable): The variable
        i (int): The index of the instruction

    Returns:
        md5: An identifier
    """

    #unique hash for bytecode
    bytecode_string = str(v)

    index_string = str(i)
    
    bytecode_index_string = bytecode_string+index_string
    md5_hash = hashlib.md5(bytecode_index_string.encode())
    hash_loc = md5_hash.hexdigest()

    return hash_loc

def generate_block_identifier_md5(i,i_offset):
    """Function to generate an md5 unique ID for a block.

    Args:
        i (_type_): _description_
        i_offset (_type_): _description_

    Returns:
        _type_: _description_
    """
    instruction_string = str(i)

    index_offset_string = str(i_offset)

    instruction_index_string = instruction_string+index_offset_string
    md5_hash = hashlib.md5(instruction_index_string.encode())
    hash_loc = md5_hash.hexdigest()

    return hash_loc

def is_valid_opcode(opcode):
    """Contains a set of all the valid opcodes

    Args:
        opcode (Literal): Opcode literal

    Returns:
        bool: true if is valid, false otherwise
    """
    s = {
        'NOP',
        'POP_TOP',
        'ROT_TWO',
        'ROT_THREE',
        'ROT_FOUR',
        'DUP_TOP',
        'DUP_TOP_TWO',

        #UNARY OPERATIONS
        
        'UNARY_POSITIVE',
        'UNARY_NEGATIVE',
        'UNARY_NOT',
        'UNARY_INVERT',
        'GET_ITER',
        'GET_YILED_FROM_ITER',

        #BINARY OPERATIONS

        'BINARY_POWER',
        'BINARY_MULTIPLY',
        'BINARY_MATRIX_MULTIPLY',
        'BINARY_FLOOR_DIVIDE',
        'BINARY_TRUE_DIVIDE',
        'BINARY_MODULO',
        'BINARY_ADD',
        'BINARY_SUBTRACT',
        'BINARY_SUBSCR',
        'BINARY_LSHIFT',
        'BINARY_RSHIFT',
        'BINARY_AND',
        'BINARY_XOR',
        'BINARY_OR',

        #INPLACE OPERATIONS

        'INPLACE_POWER',
        'INPLACE_MULTIPLY',
        'INPLACE_MATRIX_MULTIPLY',
        'INPLACE_FLOOR_DIVIDE',
        'INPLACE_TRUE_DIVIDE',
        'INPLACE_MODULO',
        'INPLACE_ADD',
        'INPLACE_SUBTRACT',
        'INPLACE_LSHIFT',
        'INPLACE_RSHIFT',
        'INPLACE_AND',
        'INPLACE_XOR',
        'INPLACE_OR',
        
        'STORE_SUBSCR',
        'STORE_SUBSCR',
        'DELETE_SUBSCR',
        
        #COROUTINE OPERATIONS

        'GET_AWAITABLE',
        'GET_AITER',
        'GET_ANEXT',
        'END_ASYNC_FOR',
        'BEFORE_ASYNC_WITH',
        'SETUP_ASYNC_WITH',

        #MISC. OPERATIONS

        'PRINT_EXPR',
        'SET_ADD',
        'LIST_APPEND',
        'MAP_ADD',
        
        'RETURN_VALUE',
        'YIELD_VALUE',
        'YIELD_FROM',
        'SETUP_ANNOTATIONS',
        'IMPORT_STAR',
        'POP_BLOCK',
        'POP_EXCEPT',
        'RERAISE',
        'WITH_EXCEPT_START',
        'LOAD_ASSERTION_ERROR',
        'LOAD_BUILD_CLASS',
        'SETUP_WITH',
        'COPY_DICT_WITHOUT_KEYS',
        'GET_LEN',
        'MATCH_MAPPING',
        'MATCH_SEQUENCE',
        'MATCH_KEYS',

        #ARGUMENT OPERATIONS

        'STORE_NAME',
        'DELETE_NAME',
        'UNPACK_SEQUENCE',
        'UNPACK_EX',
        'STORE_ATTR',
        'DELETE_ATTR',
        'STORE_GLOBAL',
        'DELETE_GLOBAL',
        'LOAD_CONST',
        'LOAD_NAME',
        'BUILD_TUPLE',
        'BUILD_LIST',
        'BUILD_SET',
        'BUILD_MAP',
        'BUILD_CONST_KEY_MAP',
        'BUILD_STRING',
        'LIST_TO_TUPLE',
        'LIST_EXTEND',
        'SET_UPDATE',
        'DICT_MERGE',
        'LOAD_ATTR',
        'COMPARE_OP',
        'IS_OP',
        'CONTAINS_OP',
        'IMPORT_NAME',
        'IMPORT_FROM',
        'JUMP_FORWARD',
        'POP_JUMP_IF_TRUE', 
        'POP_JUMP_IF_FALSE',
        'JUMP_IF_NOT_EXC_MATCH',
        'JUMP_IF_TRUE_OR_POP',
        'JUMP_IF_FALSE_OR_POP',
        'JUMP_ABSOLUTE',
        'FOR_ITER', #BUG: FIX 
        'LOAD_GLOBAL',
        'SETUP_FINALLY',
        'LOAD_FAST',
        'STORE_FAST',
        'DELETE_FAST',
        'LOAD_CLOSURE',
        'LOAD_DEREF',
        'LOAD_CLASSDEREF',
        'STORE_DEREF',
        'DELETE_DEREF',
        'RAISE_VARARGS',
        'CALL_FUNCTION',
        'CALL_FUNCTION_KW',
        'CALL_FUNCTION_EX',
        'LOAD_METHOD',
        'CALL_METHOD',
        'MAKE_FUNCTION',
        'BUILD_SLICE',
        'EXTENDED_ARG',
        'FORMAT_VALUE',
        'MATCH_CLASS',
        'GEN_START',
        'ROT_N',
        'HAVE_ARGUMENT'

    }
    if opcode in s:
        return True
    return False

def is_jump_opcode(opcode):
    """Contains a set of all the jump opcodes

    Args:
        opcode (Literal): Opcode literal

    Returns:
        bool: true if is a jump, false otherwise
    """
    s={
        'JUMP_FORWARD',
        'POP_JUMP_IF_TRUE',
        'POP_JUMP_IF_FALSE',
        'JUMP_IF_NOT_EXC_MATCH',
        'JUMP_IF_TRUE_OR_POP',
        'JUMP_IF_FALSE_OR_POP',
        'JUMP_ABSOLUTE',
        'FOR_ITER'
    }
    if opcode in s:
        return True
    return False

def is_conditional_jump_opcode(opcode):
    """Contains a set of the conditional jump opcodes ie: is opcode IF statement

    Args:
        opcode (Literal): Opcode literal

    Returns:
        bool: true if is an IF statement, false otherwise
    """
    s={
        'POP_JUMP_IF_TRUE',
        'POP_JUMP_IF_FALSE',
        'JUMP_IF_NOT_EXC_MATCH',
        'JUMP_IF_TRUE_OR_POP',
        'JUMP_IF_FALSE_OR_POP',
    }
    if opcode in s:
        return True
    return False

def get_pushes(i,instruction_arg):
    """
    Function which returns the amount of pushes to the stack
    a bytecode call makes. These are predefined values, taken from ceval.c

    Args:
        i (Instruction): is the bytecode instruction.

    Returns:
        dict[string, int]: Returns the Opname and its corresponding pushes to the stack

    """
    d = {
        'NOP': 0,
        'POP_TOP': 0,
        'ROT_TWO': 0,
        'ROT_THREE': 0,
        'ROT_FOUR': 0,
        'DUP_TOP': 1,
        'DUP_TOP_TWO': 2,

        #UNARY OPERATIONS

        'UNARY_POSITIVE': 0,
        'UNARY_NEGATIVE': 0,
        'UNARY_NOT': 0,
        'UNARY_INVERT': 0,
        'GET_ITER': 0,
        'GET_YILED_FROM_ITER': 0, #TODO: CHECK

        #BINARY OPERATIONS

        'BINARY_POWER': 1,
        'BINARY_MULTIPLY': 1,
        'BINARY_MATRIX_MULTIPLY': 1,
        'BINARY_FLOOR_DIVIDE': 1,
        'BINARY_TRUE_DIVIDE': 1,
        'BINARY_MODULO': 1,
        'BINARY_ADD': 1,
        'BINARY_SUBTRACT': 1,
        'BINARY_SUBSCR': 1,
        'BINARY_LSHIFT': 1,
        'BINARY_RSHIFT': 1,
        'BINARY_AND': 1,
        'BINARY_XOR': 1,
        'BINARY_OR': 1,

        #INPLACE OPERATIONS
        
        'INPLACE_POWER' : 0,
        'INPLACE_MULTIPLY': 0,
        'INPLACE_MATRIX_MULTIPLY': 0,
        'INPLACE_FLOOR_DIVIDE': 0,
        'INPLACE_TRUE_DIVIDE': 0,
        'INPLACE_MODULO': 0,
        'INPLACE_ADD': 0,
        'INPLACE_SUBTRACT': 0,
        'INPLACE_LSHIFT': 0,
        'INPLACE_RSHIFT': 0,
        'INPLACE_AND': 0,
        'INPLACE_XOR': 0,
        'INPLACE_OR': 0,

        'STORE_SUBSCR':0,
        'DELETE_SUBSCR':0,

        #COROUTINE OPERATIONS
        
        'GET_AWAITABLE':0,
        'GET_AITER':0,
        'GET_ANEXT':1,
        'END_ASYNC_FOR':-1, #TODO: IMPLEMENT ----> IF TOS == STOPASYNCITERATION POP 7 VALUES ELSE POP 3 VALUES
        'BEFORE_ASYNC_WITH':1, 
        'SETUP_ASYNC_WITH':0, # Not in documentation or ceval

         
        #MISC. OPERATIONS

        'PRINT_EXPR':0,
        'SET_ADD':0,
        'LIST_APPEND':0,
        'MAP_ADD':0,
        'RETURN_VALUE':0,

        'YIELD_VALUE':0,
        'YIELD_FROM':0,
        'SETUP_ANNOTATIONS':0,
        'IMPORT_STAR':0,
        'POP_BLOCK':0, # Not in documentation or ceval
        'POP_EXCEPT':0,
        'RERAISE':0,
        'WITH_EXCEPT_START':1,
        'LOAD_ASSERTION_ERROR':1,
        'LOAD_BUILD_CLASS':1,
        'SETUP_WITH':0, # Not in documentation or ceval
        'COPY_DICT_WITHOUT_KEYS':0,  # Not in documentation or ceval
        'GET_LEN':1,
        'MATCH_MAPPING':1,
        'MATCH_SEQUENCE':1,
        'MATCH_KEYS':1,

        #ARGUMENT OPERATIONS

        'STORE_NAME':0,
        'DELETE_NAME':0,
        'UNPACK_SEQUENCE':instruction_arg,
        'UNPACK_EX':0,
        'STORE_ATTR':0,
        'DELETE_ATTR':0,
        'STORE_GLOBAL':0,
        'DELETE_GLOBAL':0,
        'LOAD_CONST':1,
        'LOAD_NAME':1,
        'BUILD_TUPLE':1,
        'BUILD_LIST':1,
        'BUILD_SET':1,
        'BUILD_MAP':1,
        'BUILD_CONST_KEY_MAP':1,
        'BUILD_STRING':1,
        'LIST_TO_TUPLE':1,
        'LIST_EXTEND':0,
        'SET_UPDATE':0,
        'DICT_MERGE':0,
        'LOAD_ATTR':0,
        'COMPARE_OP':0,
        'IS_OP':0,
        'CONTAINS_OP':1,
        'IMPORT_NAME':0,
        'IMPORT_FROM':1,
        
        'JUMP_FORWARD':0,
        'POP_JUMP_IF_TRUE':0, 
        'POP_JUMP_IF_FALSE':0,
        'JUMP_IF_NOT_EXC_MATCH':0,
        'JUMP_IF_TRUE_OR_POP':0,
        'JUMP_IF_FALSE_OR_POP':0,
        'JUMP_ABSOLUTE':0,
        
        'FOR_ITER':1, #TODO: for_iter pushes 1 only if prev instruction is get_iter
        'LOAD_GLOBAL':1,
        'LOAD_FAST':1,
        'STORE_FAST':0,
        'DELETE_FAST':0,
        'LOAD_CLOSURE':1,
        'LOAD_DEREF':1,
        'LOAD_CLASSDEREF':1,
        'STORE_DEREF':0,
        'DELETE_DEREF':1,
        'RAISE_VARARGS':0,  
        'CALL_FUNCTION':1,
        'CALL_FUNCTION_KW':0,
        'CALL_FUNCTION_EX':0,
        'LOAD_METHOD':2,
        'CALL_METHOD':1,
        'MAKE_FUNCTION':1,
        'BUILD_SLICE':0,
        'EXTENDED_ARG':0,
        'FORMAT_VALUE':1,
        'MATCH_CLASS':0,
        'GEN_START':0,
        'ROT_N':0,
        }

    if i.opname in d:
        return d[i.opname]

    return 0

def get_pops(i,instruction_arg,tos):
    """
    Function which returns the amount of pops from the stack
    a bytecode call makes.

    Args:
        i (Instruction): is the bytecode instruction
        instruction_arg (int): are the arguments of the instruction
        tos(var): value at the top of the stack
    Returns:
        dict[string, int]: Returns the Opname and its corresponding pops from the stack

    """
    if tos == True:
        JUMP_IF_TRUE_OR_POP_VAL = 0
        JUMP_IF_FALSE_OR_POP_VAL = 1
    else:
        JUMP_IF_TRUE_OR_POP_VAL = 1
        JUMP_IF_FALSE_OR_POP_VAL = 0

    if i == "RAISE_VARARGS":
        if instruction_arg == 2 or instruction_arg == 1:
            RAISE_VARAGS_VAL = 1
        else:
            RAISE_VARAGS_VAL = 0
    else: RAISE_VARAGS_VAL=0
    
    if i == "BUILD_SLICE":
        if instruction_arg == 3:
            BUILD_SLICE_VAL = 2
        else:
            BUILD_SLICE_VAL = 1
    else:
        BUILD_SLICE_VAL = 0

    try:
        BUILD_MAP_VAL=(instruction_arg*2)
        BUILD_CONST_KEY_MAP_VAL=(instruction_arg+1)

    except:
        BUILD_MAP_VAL=0
        BUILD_CONST_KEY_MAP_VAL=0

    d = {
        'NOP': 0,
        'POP_TOP': 1,
        'ROT_TWO': 0,
        'ROT_THREE': 0,
        'ROT_FOUR': 0,
        'DUP_TOP': 0,
        'DUP_TOP_TWO': 0,

        #UNARY OPERATIONS

        'UNARY_POSITIVE': 0,
        'UNARY_NEGATIVE': 0,
        'UNARY_NOT': 0,
        'UNARY_INVERT': 0,
        'GET_ITER': 0,
        'GET_YILED_FROM_ITER': 0,

        #BINARY OPERATIONS

        'BINARY_POWER': 2,
        'BINARY_MULTIPLY': 2,
        'BINARY_MATRIX_MULTIPLY': 2,
        'BINARY_FLOOR_DIVIDE': 2,
        'BINARY_TRUE_DIVIDE': 2,
        'BINARY_MODULO': 2,
        'BINARY_ADD': 2,
        'BINARY_SUBTRACT': 2,
        'BINARY_SUBSCR': 2,
        'BINARY_LSHIFT': 2,
        'BINARY_RSHIFT': 2,
        'BINARY_AND': 2,
        'BINARY_XOR': 2,
        'BINARY_OR': 2,

        #INPLACE OPERATIONS

        'INPLACE_POWER': 1,
        'INPLACE_MULTIPLY': 1,
        'INPLACE_MATRIX_MULTIPLY': 1,
        'INPLACE_FLOOR_DIVIDE': 1,
        'INPLACE_TRUE_DIVIDE': 1,
        'INPLACE_MODULO': 1,
        'INPLACE_ADD': 1,
        'INPLACE_SUBTRACT': 1,
        'INPLACE_LSHIFT': 1,
        'INPLACE_RSHIFT': 1,
        'INPLACE_AND': 1,
        'INPLACE_XOR': 1,
        'INPLACE_OR': 1,

        'STORE_SUBSCR':3, #TODO: CHECK
        'DELETE_SUBSCR':2,

        #COROUTINE OPERATIONS
        
        'GET_AWAITABLE':0,
        'GET_AITER':0,
        'GET_ANEXT':0,
        'END_ASYNC_FOR':None, #TODO: IMPLEMENT ----> IF TOS == STOPASYNCITERATION POP 7 VALUES ELSE POP 3 VALUES
        'BEFORE_ASYNC_WITH':0,
        'SETUP_ASYNC_WITH':0, # Not in documentation or ceval

         #MISC. OPERATIONS

        'PRINT_EXPR':1,
        'SET_ADD':1,
        'LIST_APPEND':1,
        'MAP_ADD':2,
        'RETURN_VALUE': 1,

        'YIELD_VALUE':1,
        'YIELD_FROM':1,
        'SETUP_ANNOTATIONS':0,
        'IMPORT_STAR':1,
        'POP_BLOCK':0, # Not in documentation or ceval
        'POP_EXCEPT':3,
        'RERAISE':0,
        'WITH_EXCEPT_START':0,
        'LOAD_ASSERTION_ERROR':0,
        'LOAD_BUILD_CLASS':0,
        'SETUP_WITH':0, # Not in documentation or ceval
        'COPY_DICT_WITHOUT_KEYS':0,  # Not in documentation or ceval
        'GET_LEN':0,
        'MATCH_MAPPING':0,
        'MATCH_SEQUENCE':0,
        'MATCH_KEYS':0,

        #ARGUMENT OPERATIONS

        'STORE_NAME':1,
        'DELETE_NAME':0,
        'UNPACK_SEQUENCE':1,
        'UNPACK_EX':1,
        'STORE_ATTR':2,
        'DELETE_ATTR':1,
        'STORE_GLOBAL':1,
        'DELETE_GLOBAL':0,
        'LOAD_CONST':0,
        'LOAD_NAME':0,
        'BUILD_TUPLE':instruction_arg,
        'BUILD_LIST':instruction_arg,
        'BUILD_SET':instruction_arg,
        'BUILD_MAP': BUILD_MAP_VAL,
        'BUILD_CONST_KEY_MAP':BUILD_CONST_KEY_MAP_VAL,
        'BUILD_STRING':instruction_arg,
        'LIST_TO_TUPLE':1,
        'LIST_EXTEND':1,
        'SET_UPDATE':1,
        'DICT_MERGE':1,
        'LOAD_ATTR':0,
        'COMPARE_OP':1,
        'IS_OP':1,
        'CONTAINS_OP':2,
        'IMPORT_NAME':1,
        'IMPORT_FROM':0,
        
        'JUMP_FORWARD':0,
        'POP_JUMP_IF_TRUE':1, 
        'POP_JUMP_IF_FALSE':1,
        'JUMP_IF_NOT_EXC_MATCH':1,
        'JUMP_IF_TRUE_OR_POP':JUMP_IF_TRUE_OR_POP_VAL,
        'JUMP_IF_FALSE_OR_POP':JUMP_IF_FALSE_OR_POP_VAL,
        'JUMP_ABSOLUTE':0,
        
        'FOR_ITER':0, #TODO: for_iter pops 1 if prev instruciton is not get_iter...implement
        'LOAD_GLOBAL':0,

        'LOAD_FAST':0,
        'STORE_FAST':1,
        'DELETE_FAST':0,
        'LOAD_CLOSURE':0,
        'LOAD_DEREF':0,
        'LOAD_CLASSDEREF':0,
        'STORE_DEREF':1,
        'DELETE_DEREF':0,
        'RAISE_VARARGS':RAISE_VARAGS_VAL, 
        'CALL_FUNCTION':instruction_arg,
        'CALL_FUNCTION_KW':1,
        'CALL_FUNCTION_EX':1,
        'LOAD_METHOD':1,
        'CALL_METHOD':instruction_arg,
        'MAKE_FUNCTION':-1, #TODO:IMPLEMENT
        'BUILD_SLICE':BUILD_SLICE_VAL,
        'EXTENDED_ARG':0,
        'FORMAT_VALUE':-1,#TODO:CHECk
        'MATCH_CLASS':2,
        'GEN_START':1,
        'ROT_N':0,
        }
    if i.opname in d:
        return d[i.opname]
    
    return 0

def stack_handler(stack, instruction, identifier, instruction_arg):
    """Handles all stack operations (pushes & pops)

    Args:
        stack (list): The stack where operations are performed
        instruction (Instruction): The current instruction performing the operation 
        identifier (_type_): The identifier of the instruction
        instruction_arg (Instruction.arg): The arguments of the instruction

    Returns:
        list: The modified stack
    """
    tos = None
    opcode_name = instruction.opname
    
    if stack:
        tos = stack[-1]

    pushes = get_pushes(instruction,instruction_arg)
    pops = get_pops(instruction,instruction_arg,tos)

    if is_valid_opcode(opcode_name):
        
        for i in range(pops):
            stack.pop()

        for i in range(pushes):
            stack.append(identifier)
        
        return stack

def block_handler(previous_instruction,current_instruction,next_instruction):
    """Defines blocks based on targets and labels. New blocks start after a jump instruction
    or at a label(jump target)

    Args:
        previous_instruction (Instruction): the previous instruction
        current_instruction (Instruction): the current instruction
        next_instruction (Instruction): the next instruction

    Returns:
        boolean: true if is start of a new block, false otherwise
    """
    # used to handle the first instruction (where there are no other previous instructions)
    if(previous_instruction == None):
        return True

    previous_opcode = previous_instruction.opname
    current_opcode = current_instruction.opname
    next_opcode = next_instruction.opname
    
    # block start handler
    if(is_jump(previous_opcode)==True):
        return True
    if(is_label(current_opcode,current_instruction.is_jump_target)==True):
        return True

    # block end handler
    #if(next_instruction == None):
    #    return False
    #if(is_jump(current_opcode)==True):
    #    return False
    #if(is_label(next_opcode, next_instruction.is_jump_target)==True):
    #    return False

    return False

def is_label(opcode,jump_target):
    """Deterines if the opcode provided is a label
    Args:
        opcode (Literal): The opcode
        jump_target(bool) : If the statement is a jump target or not
    Returns:
        bool: true if the opcode is a label, false otherwise
    """
    #TODO: IMPLEMENT
    if jump_target:
        return True
    return False

def is_jump(opcode):
    """Determines if the opcode provided is a jump

    Args:
        opcode (Literal): The opcode

    Returns:
        bool: true if opcode is a jump, false otherwise
    """

    return is_jump_opcode(opcode)

def block_check(all_instructions_block,current_block_ID,pops):
    """Checks whether the instructions popped are in the same block or not 

    Args:
        all_instruction_block( set(instruction_id, block_id) ): A set of all the Instruction IDs & their block IDs 
        current_block_id(int): Current Block ID
        pops(int): is the amount of pops which are meant to be performed on the stack

    Returns:
        bool: true if the current instruction is in the same block as the instructions which are popped 
    """
    instruction_ids_block_ids = list(all_instructions_block)
    instruction_ids_block_ids.reverse()
    instruction_ids_block_ids.pop(0)
    block_ids = list()

    for i in range(pops):
        # retrieve second element from tuple
        block_ids.append(instruction_ids_block_ids[i][1])

    for i in range(len(block_ids)):
        if block_ids[i]!= current_block_ID:
            return False
    
    return True

#TODO: ADD FUNCTION TO HANDLE DICTIONARY
def is_ir_function(opname):

    ir_s = {
        'CALL_FUNCTION',
        'RETURN_VALUE',
        'BINARY_ADD',
        'BINARY_SUBTRACT',
        'BINARY_POWER'
    }

    if opname in ir_s:
        return True
    return False


def main(function):

    """
    Function which creates facts about a Python function for analysis. main makes use of recursive disassembly

    Args:
        function (code object): This is the function code object which is passed through

    Returns:
        dict(set,set,set,set,set,set,set): A dictionary of sets corresponding to fact_dict
    """

    ##INITIALIZING VARIABLES##

    global inner_code_object_address_index
    
    # holds the current function stack. stack is defined PER FUNCTION and not per block
    frame_stack = []
    prev_frame_stack = []

    # holds the current block stack. stack is defined PER BASIC BLOCK
    block_stack = list()
    prev_block_stack = list()

    # global vars
    NORMAL_BLOCK_TYPE = 'NORMAL_BLOCK_TYPE'
    IF_BLOCK_TYPE = 'IF_BLOCK_TYPE'
    ELSE_BLOCK_TYPE = 'ELSE_BLOCK_TYPE'
    LAST_LOAD_GLOBAL=''

    tos = None

    ############################################
                    ##RELATIONS##
    ############################################

    push_value = set()
    
    ##STATEMENT RELATIONS##
    
    statement_opcode = set()
    statement_next = set()
    statement_pushes = set()
    statement_pops = set()
    statement_code = set()
    statement_metadata = set()
    statement_block = set()
    statement_block_stack_delta = set()
    statement_pop_delta = set()
    statement_uses_local = list()
    statement_uses_global = list()
    statement_defines_local = set()

    statement_details = set()

    statement_block_stack_size=set()
    statement_block_head=set()
    statement_block_tail=set()

    total_statement_block_pop_delta=set()

    ##BLOCK RELATIONS##

    block_to_block=set()
    block_output_contents=list()
    block_input_contents=list()
    block_summary=set()
    block_type=set()

    ##SIMPLE IR##
    simple_statement_ir=list()

    call_functions = set()

    ############################################
            ##DICTIONARY OF RELATIONS##
    ############################################
    
    fact_dict = dict(
        PushValue=push_value,                   # set(Statement_ID: int, Value_Pushed_To_Stack: TOS)
        Statement_Pushes=statement_pushes,      # set(Statement_ID: int, Stack_Pushes:int)
        Statement_Pops=statement_pops,          # set(Statement_ID: int, Stack_Pops:int)
        Statement_Opcode=statement_opcode,      # set(Statement_ID: int, Statement_Opcode: Opcode)
        Statement_Code=statement_code,          # set(Statement_ID: int, Statement_CodeObject: code_object)
        Statement_Next=statement_next,          # set()
        Statement_Metadata=statement_metadata,  # set(Statement_ID: int, Source_code_line_number: int, Bytecode_offset: int Original_Index: int )
        Statement_Block=statement_block,        # set(Statement_ID: int, Block_ID: int)    
        Statement_Block_Stack_Delta=statement_block_stack_delta, #set(Statement_ID: int, Stack_Position: int)
        Statement_Pop_Delta=statement_pop_delta, #set(Statement_ID: int, Pop_Delta:int)
        Statement_Uses_Local=statement_uses_local,           #list(Statement_ID:int, Variable_Identifier:int, Positional_argument:int) -> first is the current instruction, second is the id of the variable used
        Statement_Uses_Global=statement_uses_global,           #list(Statement_ID:int, Variable_Identifier:int, Positional_argument:int) -> first is the current instruction, second is the id of the variable used
        Statement_Defines_Local=statement_defines_local,        #set(Statement_ID:int,Variable_Identifier:variable)

        Statement_Details=statement_details, #set(Statement_ID, Block_ID ,Push_Value,opcode,Line_Number)

        Statement_Block_Stack_Size=statement_block_stack_size, #set(Statement_ID: int, Stack_Size: int)
        Statement_Block_Head=statement_block_head, #set(Statement_ID: int, Block_ID: int)
        Statement_Block_Tail=statement_block_tail, #set(Statement_ID: int, Block_ID: int)

        Total_Statement_Block_Pop_Delta=total_statement_block_pop_delta, #set(Statement_ID: int, Running_Pop_Count: int)
        
        Block_To_Block=block_to_block, #set(Current_Block_ID: int, Next_Block_ID: int)
        Block_Output_Contents=block_output_contents, #set(Block_ID:int,Live_Instruction:Instruction_ID)
        Block_Input_Contents=block_input_contents, #set(Block_ID:int,Live_Instruction:Instruction_ID)
        Block_Summary = block_summary, #set(Block_ID: int, Start_Statement: Statement_ID, End_Statement: Statement_ID, Start_offset:int, End_offset:int)
        ## BLOCK TYPE -> NORMAL, IF_BLOCK<<if_block_identifier>>, ELSE_BLOCK<<else_block_identifier>>
        ## the if blocks and else blocks are linked by the if_block_identifier and the else_block_identifier. An
        # if identifier cannot be connected to an else identifier in the cfg 
        Block_Type = block_type, #set(Block_ID:int, Block_Type: blockType, Block_Link_)

        Simple_Statement_IR = simple_statement_ir,

        Call_Functions=call_functions
    )
    bytecode = dis.Bytecode(function)
    

    # find the total amount of bytecode instructions
    instructions_list = list(dis.get_instructions(function))

    instructions_offset_list = list()

    for i in range(len(instructions_list)):
        instructions_offset_list.append(instructions_list[i].offset)

    instruction_size = len(instructions_list)
    largest_bytecode_offset = instructions_list[instruction_size-1].offset

    block_identifier = None
    prev_block_identifier = -1

    prev_instruction = None
    prev_instruction_identifier = -1
    next_instruction = None
    line_number = 0

    #total amount of pops in the block
    running_pop_delta=0

    for i, instruction in enumerate(bytecode):
        
        try:
            
            if is_valid_opcode(instruction.opname):   

                ############################################
                ##SETTING UP CURRENT INSTRUCTION VARIABLES##
                ############################################
                
                # SETTING NEXT INSTRUCTION
                if instruction.offset<largest_bytecode_offset:
                    next_instruction = instructions_list[i+1]

                # INSTRUCTION VARIABLES
                instruction_arg = instruction.arg
                instruction_identifier = generate_statement_identifier_md5(bytecode, i)
                instruction_pop_delta = get_pops(instruction,instruction_arg,tos)
                if instruction.opname == 'LOAD_GLOBAL':
                    LAST_LOAD_GLOBAL = instruction.argval #used for function name
                
                ############################################
                  ##SETTING UP INSTRUCTION LINE NUMBERS##
                ############################################

                # line number generator
                if(instruction.starts_line!=None):
                    line_number = instruction.starts_line
                
                bytecode_offset = instruction.offset
                
                # line_arg is in the format -> <line_number>.<bytecode_offset>
                line_arg = line_number + (bytecode_offset/(largest_bytecode_offset+1))

                ############################################
                        ##SETTING UP THE BLOCK##
                ############################################
                
                # BLOCK VARIABLES

                is_new_block = block_handler(prev_instruction,instruction,next_instruction)
                # if the instruction is in a new block, set the new block variables 
                if(is_new_block):
                    
                    #block identifier for new block
                    block_identifier = generate_block_identifier_md5(i,instruction.offset)
                    
                    statement_block_head.add((instruction_identifier,block_identifier)) # setting head of current block
                    statement_block_tail.add((prev_instruction_identifier,prev_block_identifier)) # setting tail of previous block

                    # a block_link_id uniquely identifies a link between two blocks
                    block_link_id = generate_block_link_identifier_md5(prev_block_identifier,block_identifier)
                    
                    ############################################
                            ##CONTROL FLOW HANDLER##
                    ############################################

                    # ensuring is not first instruction
                    if prev_instruction:
                        # condition when control flow splits into different blocks
                        # since generate_block_identifier_md5 generates the same hash for the same input given, only one pass is needed
                        # to determine the edges between branching statements 
                        
                        # handling of the else branch block
                        if is_jump_opcode(prev_instruction.opname):
                            
                            # if the previous instruction was a jump opcode, new block is an if section, and offset of 
                            # the jump opcode is the else section.

                            # handling of the else branch block
                            offset_jump_destination = prev_instruction.argval
                            index_next_block = instructions_offset_list.index(offset_jump_destination)
                            branch_block_identifier = generate_block_identifier_md5(index_next_block,offset_jump_destination)

                            if is_conditional_jump_opcode(prev_instruction.opname):
                                # handling the if branch relation 
                                block_to_block.add((prev_block_identifier,block_identifier))

                            # handling the else branch relation
                            block_to_block.add((prev_block_identifier,branch_block_identifier))
                        
                            # if it is a conditional jump 
                            if is_conditional_jump_opcode(prev_instruction.opname):
                                block_type.add((block_identifier,IF_BLOCK_TYPE,block_link_id))
                                block_type.add((branch_block_identifier,ELSE_BLOCK_TYPE,block_link_id))
                        else:
                            block_to_block.add((prev_block_identifier,block_identifier))
                            #block_type.add((branch_block_identifier,NORMAL_BLOCK_TYPE,block_link_id))


                    else:
                        # if it is the first instruction... -1 marks entry point 
                        block_to_block.add((-1,block_identifier))



                    # handler for empty blockstack
                    if not block_stack:
                        block_output_contents.append((None,prev_block_identifier))
                        block_input_contents.append((None,block_identifier))

                    else:    
                        # adding the outputs of the previous block
                        for active_instruction in block_stack:
                            block_output_contents.append((active_instruction,prev_block_identifier))

                        # adding the inputs of this block
                        for active_instruction in block_stack:
                            block_input_contents.append((active_instruction,block_identifier))

                        block_stack.clear()

                        ## List reversing to copy blockstack

                        tmp_list=block_input_contents.copy()

                        for x in range(len(block_input_contents)):
                            tmp_item=tmp_list[x]
                            
                            #check if item pertains to block
                            if tmp_item[1] == block_identifier:
                                block_stack.append(tmp_item[0])

                    running_pop_delta = 0

                block_stack = stack_handler(block_stack,instruction,instruction_identifier,instruction_arg)

                # set the block pop delta
                running_pop_delta += instruction_pop_delta

                # if you have reached the final instruction set the tail (edge condition) and exit block
                if i==instruction_size-1:
                    statement_block_tail.add((instruction_identifier,block_identifier))
                    block_to_block.add((block_identifier,-1))

                ############################################
                    ##DELEGATE WORK TO OPCODE HANDLER##
                ############################################

                # MODIFYING STACK
                frame_stack = stack_handler(frame_stack,instruction,instruction_identifier,instruction_arg)
                
                if frame_stack:
                    tos=frame_stack[-1]

                # SETTING RELATIONS
                push_value.add((instruction_identifier, instruction.argval))

                statement_opcode.add((instruction_identifier, instruction.opname))
                statement_pushes.add((instruction_identifier, get_pushes(instruction,instruction_arg)))
                statement_pops.add((instruction_identifier, get_pops(instruction,instruction_arg,tos)))
                statement_code.add((instruction_identifier, str(function)))
                statement_metadata.add((instruction_identifier,line_arg))
                statement_block.add((instruction_identifier,block_identifier))
                
                #TODO: FIX THE FOLLOWING
                #statement_defines_local.add((instruction_identifier,variable_identifier))
                statement_pop_delta.add((instruction_identifier,instruction_pop_delta))
                total_statement_block_pop_delta.add((instruction_identifier,running_pop_delta))

                statement_block_stack_size.add((instruction_identifier,len(block_stack)))

                statement_details.add((instruction_identifier,block_identifier,instruction.opname,line_arg,instruction.argval))

                # SETTING NEXT INSTRUCTION
                if prev_instruction:
                    statement_next.add((instruction_identifier, prev_instruction_identifier))
                else:
                    statement_next.add((instruction_identifier, -1))
                
                ##STATEMENT_USES##
                # SETTING LOCAL_STATEMENT_USES
                if block_check(statement_block,block_identifier,instruction_pop_delta) == True :
                    
                    # iterating through pops -> a statement uses an instruction it pops
                    for i in range(instruction_pop_delta):
                        
                        used_instruction_id = prev_frame_stack[-(i+1)] # obtaining values starting from the previous TOS
                        statement_uses_local.append((instruction_identifier,used_instruction_id,i))
                
                # SETTING GLOABL_STATEMENT_USES
                for i in range(instruction_pop_delta):
                        used_instruction_id = prev_frame_stack[-(i+1)] # obtaining values starting from the previous TOS
                        statement_uses_global.append((instruction_identifier,used_instruction_id,i))

                # SETTING THE BLOCK STACK DELTA
                stack_delta = len(block_stack)-len(prev_block_stack)
                statement_block_stack_delta.add((instruction_identifier,stack_delta))


                ############################################
                        ##IR OPCODE HANDLING##
                ############################################
                if is_ir_function(instruction.opname):

                    used_instructions=set()
                    used_instruction_args=list()
                    var_identifier = None

                    for local_instruction in statement_uses_global:
                        if instruction_identifier == local_instruction[0]:
                            used_instructions.add((local_instruction[1],local_instruction[2]))

                    for local_instruction in push_value:
                        for used_instruction in used_instructions:
                            if used_instruction[0]== local_instruction[0]:
                                used_instruction_args.insert(used_instruction[1], local_instruction[1])
                    
                    if next_instruction:
                        if next_instruction.opname == 'STORE_FAST':
                            var_identifier=next_instruction.argval

                    #if var_identifier!=None:
                        #tuple_string = (str(instruction_identifier) + "\t" + str(var_identifier) + " = " +str(instruction.opname) + "\t" + str(used_instruction_args))
                    #else:
                        #tuple_string = (str(instruction_identifier) + "\t" +str(instruction.opname) + "\t" + str(used_instruction_args))

                    #print(tuple_string)
                    tuple = ir_rep_handler(instruction_identifier,var_identifier,instruction.opname,used_instruction_args,LAST_LOAD_GLOBAL)
                    print(tuple)
                    #TODO:add file saving
                    simple_statement_ir.append(tuple)

                ############################################
                        ##SPECIAL OPCODE HANDLING##
                ############################################

                #TODO: Verify Make function !!!
                if instruction.opname == 'MAKE_FUNCTION':
                    inner_code_object = list(bytecode)[i-2].argval
                    inner_fact_dict = main(inner_code_object)

                    for k,v in inner_fact_dict.items():
                        if type(v) is set:
                            d =  fact_dict[k]
                            d |= v
                        elif type(v) is list:
                            d =  fact_dict[k]
                            d += v

                
                #TODO: ADD CALL_FUNCTION
                if instruction.opname == 'CALL_FUNCTION':
                    #TODO:REMOVE print functions...system specific
                    #TODO: add args to allow for overloaded functions
                    call_functions.add((function.co_filename,LAST_LOAD_GLOBAL))

                continue
            else:
                raise Exception("A bytecode instruction that is not supported has been detected.\n To avoid inaccurate analysis, program will exit")
        finally:

            ############################################
                    ##UPDATING GLOBAL VARS##
            ############################################

            prev_block_identifier = block_identifier
            prev_instruction = instruction
            prev_instruction_identifier = instruction_identifier
            block_type_1 = type(block_stack)
            frame_type_1 = type(frame_stack)
            prev_frame_stack = frame_stack.copy()
            prev_block_stack = block_stack.copy()
    
    ##SUMMARIZING BLOCKS##
    #TODO: add more info to block summary.

    amount_of_blocks = len(statement_block_head)

    tmp_statement_block_head = list(statement_block_head)
    tmp_statement_block_tail = list(statement_block_tail)

    for block in range(amount_of_blocks):
        block_id = tmp_statement_block_head[block][1]

        block_head = ([blocks for blocks in tmp_statement_block_head 
                      if blocks[1] == block_id])[0][0]

        block_tail = [blocks for blocks in tmp_statement_block_tail 
                      if blocks[1] == block_id][0][0]

        block_summary.add((block_id,block_head,block_tail))

    return fact_dict

def ir_rep_handler(instruction_identifier,variable_identifier,instruction_name,used_instruction_args,last_load_global):

    tuple_string=None
    # sanity check for arguments
    if not used_instruction_args:
        used_instruction_args.append(None)

    if instruction_name == 'BINARY_ADD':
        if(variable_identifier is not None):
            tuple_string = (str(instruction_identifier) + "\t" + str(variable_identifier) + " = " +str(instruction_name) + "\t" + str(used_instruction_args[1]) + " + " + str(used_instruction_args[0]))
        else:
            tuple_string = (str(instruction_identifier) + "\t" +str(instruction_name) + "\t" + str(used_instruction_args[1]) + " + " + str(used_instruction_args[0]))
            
    elif instruction_name == 'BINARY_SUBTRACT':
        if(variable_identifier is not None):
            tuple_string = (str(instruction_identifier) + "\t" + str(variable_identifier) + " = " +str(instruction_name) + "\t" + str(used_instruction_args[1]) + " - " + str(used_instruction_args[0]))
        else:
            tuple_string = (str(instruction_identifier) + "\t" +str(instruction_name) + "\t" + str(used_instruction_args[1]) + " - " + str(used_instruction_args[0]))

    elif instruction_name == 'BINARY_POWER':
        tuple_string = (str(instruction_identifier) + "\t" + str(variable_identifier) + " = " +str(instruction_name) + "\t" + str(used_instruction_args[1]) + "^" + str(used_instruction_args[0]))

    elif instruction_name == 'RETURN_VALUE':
        tuple_string = (str(instruction_identifier) + "\t" +str(instruction_name) + "\t" + str(used_instruction_args[0]))

    elif instruction_name == 'CALL_FUNCTION':
        if used_instruction_args[0] is None:
            tuple_string = (str(instruction_identifier) + "\t" + str(instruction_name) + "\t" + str(last_load_global) + "\t" +"NO ARGS")
        else:
            used_instruction_args.reverse()
            tuple_string = (str(instruction_identifier) + "\t" +str(instruction_name) + "\t" + str(last_load_global) + "\t" +str(used_instruction_args))

    return tuple_string

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
    DEPRECATED
    Function which handles the generation of the line number table. 

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
        #function_path = "/Users/andretheuma/Documents/Andre/Andre's documents/School/UoM Computing Science/3RD Year/FYP/CS_Final_Year_Project/Python Bytecode Analyzer/project/functions/addition_with_parms.py"
        #function = init_function(function_path)
        #dis.dis(function)
        # functions_list=getmember
        print("-------------------")
        print("Starting PATH...")
        print("-------------------")
        #TODO: add functionality to detect class
        #test_var=program_function.Address
        code_object = program_function.main.__code__
        print("Analysing: " + code_object.co_filename + " \nFunction name: " + code_object.co_name)
        
        dis.dis(code_object)
        start_time = time.time()

        out_obj = main(code_object)
        end_time = time.time()
        total = end_time-start_time

        print("-------------------")
        print("Time Elapsed: " + str(total) + " seconds.")

        sorter = sorting_handler()
        sorted_stmt_metadata = sorter.sort_metadata(out_obj)
        
        #TODO: Add file hierarchy 

        sorted_push = sorter.general_stmt_sorter(out_obj,'PushValue')
        sorted_stmt_pushes = sorter.general_stmt_sorter(out_obj,'Statement_Pushes')
        sorted_stmt_pops = sorter.general_stmt_sorter(out_obj,'Statement_Pops')
        sorted_stmt_opcode = sorter.general_stmt_sorter(out_obj,'Statement_Opcode')
        sorted_stmt_code = sorter.general_stmt_sorter(out_obj,'Statement_Code')
        #sorted_stmt_next = sorter.general_stmt_sorter(out_obj,'Statement_Next')
        sorted_stmt_metadata = sorter.general_stmt_sorter(out_obj,'Statement_Metadata')
        sorted_stmt_block = sorter.general_stmt_sorter(out_obj,'Statement_Block')
        sorted_stmt_block_stack_delta = sorter.general_stmt_sorter(out_obj,'Statement_Block_Stack_Delta')
        sorted_stmt_pop_delta = sorter.general_stmt_sorter(out_obj,'Statement_Pop_Delta')
        #sorted_stmt_uses_local = sorter.general_stmt_sorter(out_obj,'Statement_Uses_Local')
        sorted_stmt_defines_local = sorter.general_stmt_sorter(out_obj,'Statement_Defines_Local')
        sorted_stmt_next = sorter.general_stmt_sorter(out_obj,'Statement_Next')

        sorted_block_stack_size = sorter.general_stmt_sorter(out_obj,'Statement_Block_Stack_Size')
        sorted_block_head = sorter.general_stmt_sorter(out_obj,'Statement_Block_Head')
        sorted_block_tail = sorter.general_stmt_sorter(out_obj,'Statement_Block_Tail')

        sorted_total_statement_block_pop_delta = sorter.general_stmt_sorter(out_obj,'Total_Statement_Block_Pop_Delta')

        # init file handler
        file = file_handler()

        file.save_to_csv(sorted_push, "PushValue")
        file.save_to_csv(sorted_stmt_metadata, "StatementMetadata")
        file.save_to_csv(sorted_stmt_pushes, "StatementPushes")
        file.save_to_csv(sorted_stmt_pops, "StatementPops")
        file.save_to_csv(sorted_stmt_opcode, "StatementOpcode")
        file.save_to_csv(sorted_stmt_code, "StatementCode")
        file.save_to_csv(sorted_stmt_block,"StatementBlock")
        #file.save_to_csv(sorted_stmt_stack_delta,"StatementStackDelta")
        file.save_to_csv(sorted_stmt_block_stack_delta,"StatementStackDelta")
        file.save_to_csv(sorted_stmt_pop_delta,"StatementPopDelta")
        
        #TODO: ADD FILE SAVING FOR STATEMENT_USES and STATEMENT_DEFINES
        file.save_to_csv(sorted_stmt_defines_local,"StatementDefinesLocal")
        file.save_to_csv(sorted_stmt_next,"StatementNext")
        file.save_to_csv_three_tuple(out_obj['Statement_Uses_Local'],"StatementUsesLocal")
        
        file.save_to_csv_five_tuple(out_obj['Statement_Details'],"StatementDetails")

        file.save_to_csv(sorted_block_stack_size,"StatementBlockStackSize")
        file.save_to_csv(sorted_block_head,"StatementBlockHead")
        file.save_to_csv(sorted_block_tail,"StatementBlockTail")

        file.save_to_csv(sorted_total_statement_block_pop_delta,"TotalStatementPopDelta")
        
        file.save_to_csv(out_obj['Block_Input_Contents'],"BlockInputContents")
        file.save_to_csv(out_obj['Block_Output_Contents'],"BlockOutputContents")
        
        file.save_to_csv(out_obj['Block_To_Block'],"BlockToBlock")

        file.save_to_csv_three_tuple_string(out_obj['Block_Summary'],"BlockSummary")
        file.save_to_csv_three_tuple_string(out_obj['Block_Type'],"BlockType")
        #file.save_to_csv(out_obj['Simple_Statement_IR'],"SimpleIR")

        file.save_to_csv(out_obj['Call_Functions'], "FunctionsNotAnalysed")
        
        print("Files saved to: " + os.getcwd() + "/resources")

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


    \section{Technical Implementation}
            
            begin{description}
                \item Global Instruction Variables monitor several attributes of the individual bytecode instructions:
                \item[prev\_instruction] keeps track of instruction textsubscript{i-1}. Previous instructions are useful as they allow for proper block creation, and are vital for the generation of control flow graphs.
                \item[prev\_instruction\_identifier] records the previous instruction identifier. The identifier is stored in a separate variable, and not extracted from \lstinline|prev_instruction| for the sake of brevity. Variable is initialized to {bfseries-1}, indicating the start of the program.
                \item[instruction\_list] produces a list of all the bytecode instructions that will be enumerated through in the acs{AIL}. This list is immediately created to ease the creation of other metrics, such as obtaining the total amount of instructions. 
                \item[next\_instruction] pulls the next instruction from \lstinline|instruction_list|, if there is a next instruction. This variable is used for correct block handling and acs{IR} generation.
                \item[instruction\_size] finds the amount of bytecode instructions there are in the current scope, that need to be read. Variable is initialized.
                \item[instructions\_offset\_list] stores all the offsets of the bytecode instructions. It is interesting to note, that through this dissertation it has been discovered that bytecode instructions are always 2 bytes in size. Each byte is reserved for the opcode and oparg respectively.
                \item[largest\_bytecode\_offset] stores the largest bytecode offset. This represents the last instruction, and is used to generate an upper limit for the custom line number argument. Variable is initialized.
                \item[line\_number] monitors the current line number argument of each bytecode instruction. Bytecode instructions do not always have a line number, indicating that the instruction is between line numbers. When an instruction is in such a state, it relies on the custom line number argument. %%TODO: add correct ref
            \end{description}

            begin{description}
                \item Global Block Variables perform a vital role in distinguishing blocks; useful for block analysis.
                \item[block\_identifier] keeps track of the current instruction block.
                \item[prev\_block\_identifier] records the previous block identifier. Variable is initialized to {bfseries-1}, indicating the first block of the program.
            \end{description}

            begin{description}
                \item The following variables form part of the Miscellaneous Variables. These form part of the backbone structure of acs{PATH}:
                \item[frame\_stack] acts as a frame stack, having instructions pushed onto and popped off of accordingly. This stack is flushed with every new function call.
                \item[prev\_frame\_stack] records the previous frame stack, from a previous function call. %%TODO: MAYBE REMOVE...no use
                \item[block\_stack] acts as a stack, having instructions pushed onto and popped off of accordingly. This stack is flushed with every new block. An interesting insight that was discovered is that Python operates in a way whereby prior to exiting a block, no instructions are left on the stack.
                \item[prev\_block\_stack] records the previous block stack.
                \item[tos] stores the value at the top of the stack. Variable is used for convenience.
                \item[bytecode] stores the disassembled code object.  
            \end{description}
        
            begin{description}
                \item The following variables are global constants, used to classify elementary blocks.
                \item[NORMAL\_BLOCK\_TYPE] represents a normal elementary block.
                \item[IF\_BLOCK\_TYPE] represents the if branch of a conditional instruction.
                \item[ELSE\_BLOCK\_TYPE] represents the else branch of a conditional instruction.
            \end{description}

            begin{description}
                \item[instruction\_arg] 
            \end{description}

            andre(FINISH)

'''
