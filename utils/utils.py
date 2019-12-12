def get_instruction_list(code_manager, function):
    """
    Get list of instructions in the function.

    :param function: Function to parse for instruction list.

    :returns: List of instructions.
    """
    if function is None:
        return []
    function_bounds = function.getBody()
    function_instructions = code_manager.getInstructions(function_bounds, True)
    return function_instructions


def get_function(function_manager, address):
    """
    Return the function that contains the address. 

    :param address: Address within function.

    :returns: Function that contains the provided address.
    """
    return function_manager.getFunctionContaining(address)


def is_call_instruction(instruction):
    """
    Determine if an instruction calls a function.

    :param instruction: Instruction to inspect.
    :type instruction: ghidra.program.model.listing.Instruction

    :returns: True if the instruction is a call, false otherwise.
    :rtype: bool
    """
    if not instruction:
        return False

    flow_type = instruction.getFlowType()
    return flow_type.isCall()


def get_processor(current_program):
    """
    Get string representing the current programs processor.

    :param current_program: Current program loaded in Ghidra.
    :type current_program: ghidra.program.model.listing.Program.
    """
    language = current_program.getLanguage()
    return language.getProcessor().toString()


def find_function(current_program, function_name):
    """
    Find a function, by name, in the current program.

    :param current_program: Current program loaded in Ghidra.
    :type current_program: ghidra.program.model.listing.Program

    :param function_name: Function to search for.
    :type function_name: str
    """
    listing = current_program.getListing()
    if listing:
        return listing.getGlobalFunctions(function_name)
    return []


def address_to_int(address):
    """
    Convert Ghidra address to integer.

    :param address: Address to convert to integer.
    :type address: ghidra.program.model.address.Address

    :returns: Integer representation of the address.
    :rtype: int
    """
    return int(address.toString(), 16)


def allowed_processors(current_program, processor_list):
    """
    Function to prevent scripts from running against unsupported processors.

    :param current_program: Current program loaded in Ghidra.
    :type current_program: ghidra.program.model.listing.Program

    :param processor_list: List of supported processors.
    :type processor_list: list(str)
    """
    curr_processor = get_processor(current_program)

    if curr_processor not in processor_list:
        print '%s is not a valid processor for this script. Supported ' \
            'processors are: %s' % (curr_processor, processor_list)
        exit(1)
