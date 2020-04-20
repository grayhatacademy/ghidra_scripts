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


def is_jump_instruction(instruction):
    """
    Determine if instruction is a jump.

    :param instruction: Instruction to inspect.
    :type instruction: ghidra.program.model.listing.Instruction

    :returns: True if the instruction is a jump, false otherwise.
    :rtype: bool
    """
    if not instruction:
        return False

    flow_type = instruction.getFlowType()
    return flow_type.isJump()


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


def table_pretty_print(title, entries):
    """
    Print a simple table to the terminal.

    :param title: Title of the table.
    :type title: list

    :param entries: Entries to print in the table.
    :type entries: list(list(str))
    """
    # Pad entries to be the same length
    entries = [entry + ([''] * (len(title) - len(entry))) for entry in entries]
    lines = [title] + entries

    # Find the largest entry in each column so it can be used later
    # for the format string. Drop title entries if an entire column is empty.
    max_line_len = []
    for i in range(0, len(title)):
        column_lengths = [len(line[i]) for line in lines]
        if sum(column_lengths[1:]) == 0:
            title = title[:i]
            break
        max_line_len.append(max(column_lengths))

    # Account for largest entry, spaces, and '|' characters on each line.
    separator = '=' * (sum(max_line_len) + (len(title) * 3) + 1)
    spacer = '|'
    format_specifier = '{:<{width}}'

    # First block prints the title and '=' characters to make a title
    # border
    print separator
    print spacer,
    for width, column in zip(max_line_len, title):
        print format_specifier.format(column, width=width),
        print spacer,
    print ''
    print separator

    # Print the actual entries.
    for entry in entries:
        print spacer,
        for width, column in zip(max_line_len, entry):
            print format_specifier.format(column, width=width),
            print spacer,
        print ''
    print separator
