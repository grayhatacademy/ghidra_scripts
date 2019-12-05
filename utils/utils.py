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
