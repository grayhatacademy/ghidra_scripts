# Fixup .text section by defining all undefined code and converting it to a function if applicable.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Codatify.Fixup Code

import time

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import FlowType

# Adjust to your own preference.
FUNCTION_PREFIX = 'CFUN_%s'


def get_section(section):
    """
    Find section in the code by name.

    :param section: Section to find.
    :type section: str

    :returns: Section if found, None otherwise.
    :rtype: ghidra.program.model.listing.ProgramFragment
    """
    listing = currentProgram.getListing()
    return getFragment(listing.getRootModule(0), section)


def is_valid_function_end(last_instruction):
    """
    Rudimentary valid function checker. Simply checks the last instruction for a 
    terminating instruction, taking into account delay slots.

    :param last_instruction: Last instruction in a function.
    :type last_instruction: ghidra.program.model.listing.Instruction

    :returns: True if valid function, False otherwise. 
    """
    if last_instruction is None:
        return False

    if last_instruction.isInDelaySlot():
        last_instruction = getInstructionAt(last_instruction.getFallFrom())

    if last_instruction.getFlowType() == FlowType.TERMINATOR:
        return True
    return False


def find_function_end(function, max_address, instruction_length):
    """
    Find the last instruction in a newly created function up to a maximum 
    address to prevent overrun into previously defined code.

    :param function: Newly created function to find end address.
    :type function: ghidra.program.model.listing.Function

    :param max_address: Max address to return.
    :type max_address: ghidra.program.model.listing.Address

    :param instruction_length: Instruction length to account for the functions
                               max address functionality returning a value that 
                               representing the last byte of the last instruction.
    :type instruction_length: int

    :returns: Last instruction in the function.
    :rtype: ghidra.program.model.listing.Instruction
    """
    if not function:
        raise Exception('Invalid function provided.')
    if not max_address:
        raise('Invalid max address provided.')

    # Fix-up function max address to be aligned on the instruction length
    # boundary. MIPS at least returns the last byte of the last instruction
    # which is not on the required 4 byte boundary.
    function_max = function.getBody().getMaxAddress()
    function_max = function_max.subtract(
        function_max.getOffset() % instruction_length)

    comparison = function_max.compareTo(max_address.getAddress())
    if comparison == 1:
        return max_address
    return getInstructionAt(function_max)


def clear_listing(addr_list, symbols=False, function=False, register=False):
    """
    Remove symbols, function, or registers from the list of addresses. 
    Attempting to remove multiple entries concurrently may lead to an 
    exception.

    :param addr_list: List of addresses to clear listings from.
    :type addr_list: list(ghidra.program.model.listing.Address)

    :param symbols: Remove symbol listing.
    :type symbols: bool

    :param function: Remove function listing.
    :type function: bool

    :param register: Remove register listing.
    :type register: bool
    """
    addr_factory = getAddressFactory()
    if not addr_factory:
        raise Exception("Failed to get address factory.")

    for addr in addr_list:
        addr_set = addr_factory.getAddressSet(addr, addr)
        clearListing(addr_set, False, symbols, False, False, function, register,
                     False, False, False, False, False, False)


def define_code_and_functions(section):
    """
    Convert undefined code in the section provided to defined code and a 
    function if applicable.

    :param section: Section to search for undefined code.
    :type section: ghidra.program.model.listing.ProgramFragment
    """
    function_count = 0
    code_block_count = 0
    invalid_functions = []

    if section is None:
        return

    start_addr = section.getMinAddress()
    end_addr = section.getMaxAddress()

    undefined_code = getUndefinedDataAt(start_addr)
    if undefined_code is None:
        undefined_code = getUndefinedDataAfter(start_addr)

    # Loop through all undefined code in the provided section.
    while undefined_code is not None and undefined_code.getAddress() < end_addr:
        undefined_addr = undefined_code.getAddress()
        next_valid_ins = getInstructionAfter(undefined_addr)

        try:
            disassemble(undefined_addr)

            instruction_length = getInstructionAt(undefined_addr).getLength()
            last_invalid_ins = getInstructionBefore(
                next_valid_ins.getAddress())

            # Create a function around the code and check for validity.
            new_func = createFunction(
                undefined_addr, FUNCTION_PREFIX % undefined_addr)

            if new_func is None:
                continue

            last_instruction = find_function_end(
                new_func, last_invalid_ins, instruction_length)

            if is_valid_function_end(last_instruction):
                function_count += 1
            else:
                invalid_functions.append(undefined_addr)
                code_block_count += 1
        except:
            continue
        finally:
            undefined_code = getUndefinedDataAfter(undefined_addr)

    # If the functions are removed immediately it will cause some race condition
    # exceptions to be raised with Call Fix-up routine. If all listings are
    # removed in one go it raises an exception, sometimes.
    clear_listing(invalid_functions, symbols=True)
    time.sleep(1)
    clear_listing(invalid_functions, function=True)
    time.sleep(1)
    clear_listing(invalid_functions, register=True)

    print 'Converted {} undefined code block and created {} new functions.'.format(
        code_block_count, function_count)


curr_section = get_section('.text')
define_code_and_functions(curr_section)
