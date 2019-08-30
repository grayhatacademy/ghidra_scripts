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