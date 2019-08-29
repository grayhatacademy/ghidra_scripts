#Find local references to selected registers and local variables in the current function.
#@author fuzzywalls
#@category TNS
#@keybinding 
#@menupath TNS.Local X-Refs


import re
from ghidra.program.model.listing import CodeUnit

class InstructionMatch(object):
    def __init__(self, address, direction, ref_type, instruction):
        self.address = address
        self.direction = direction
        self.ref_type = ref_type
        self.instruction = instruction

    def __str__(self):
        return '{:7} {:10} {:12} {}'.format(self.direction, 
                                            self.ref_type, 
                                            self.address, 
                                            self.instruction) 


def get_function(address):
    """
    Return the function that contains the address. 
    
    :param address: Address within function.
    
    :returns: Function that contains the provided address.
    """
    function_manager = currentProgram.getFunctionManager()
    return function_manager.getFunctionContaining(address)


def get_instruction_list(function):
    """
    Get list of instructions in the function.
    
    :param function: Function to parse for instruction list.
    
    :returns: List of instructions.
    """
    code_manager = currentProgram.getCodeManager()
    function_bounds = function.getBody()
    function_instructions = code_manager.getInstructions(function_bounds, True)
    return function_instructions


def get_sub_operation(selection):
    """
    Get sub operation within operation. Usually a register offset. 
    
    :param selection: Current mouse selection.
    
    :returns: Sub operation within current operation.
    """
    sub_index = currentLocation.getSubOperandIndex()
    split_selection = re.findall(r"[\w']+", selection)
    index = 0 if sub_index == 0 else 1
    try:
        sub_operation = split_selection[index]
    except IndexError:
        sub_operation = split_selection[0]
        
    return sub_operation


def process_function_call(operation, offset):
    """
    Process function calls to determine if the register or function is selected.
    
    :param operation: Full operation to process.
    :param offset: Offset of mouse in the operation.
    
    :returns: Selected item in the operation.
    """
    equal_index = operation.index('=>')
    items = operation.split('=>')
    if offset < equal_index:
        return items[0]
    return items[1]


def get_selection(current_function, force_address=False):
    """
    Get the current selection.

    :param function: Function that contains the selection.
    :param force_address: Force the use of the raw address, used to process 
                          labels.

    :returns: String representing the current selection.
    """
    # If the selection is a label this will not throw an exception.
    try:
        selection = currentLocation.getName()
        print '\nXrefs to {} in {}:'.format(selection, current_function)
    except AttributeError:
        try:
            is_variable = currentLocation.getVariableOffset()
            if is_variable is not None:
                variable = currentLocation.getRefAddress()
                stack = current_function.getStackFrame()
                stack_size = stack.getFrameSize()
                stack_variable = stack_size + variable.getOffset()
                selection = hex(stack_variable)[:-1]
                print '\nXrefs to {}({}) in {}:'.format(selection, 
                                                          is_variable,
                                                          current_function)
            elif force_address:
                address = currentLocation.getRefAddress().getOffset()
                selection = str.format('0x{:08x}', address)
                print '\nXrefs to {} in {}:'.format(selection, current_function)
            else:
                selection = currentLocation.getOperandRepresentation()
                if '=>' in selection:
                    selection = process_function_call(
                        selection, currentLocation.getCharOffset())
                selection = get_sub_operation(selection) 
                print '\nXrefs to {} in {}:'.format(selection, current_function)

        except AttributeError:
            print 'No value selected.'
            exit() 

    print '-' * 60
    return selection


def check_flows(instruction, target):
    """
    Search instruction flows to see if they match the target.
    
    :param instruction: Current instruction.
    :param target: Target instruction.
    
    :returns: True if a flow matches the target, False otherwise.
    """
    flows = instruction.getFlows()
    for flow in flows:
        if flow.toString() in target:
            return True
    return False

def create_match(instruction, index=0):
    """
    Create instruction match class from instruction and the operand index.
    """
    ins_addr = instruction.getAddress()
    if ins_addr > currentLocation.address:
        direction = 'DOWN'
    elif ins_addr < currentLocation.address:
        direction = 'UP'
    else:
        direction = '-'
    ref_type = instruction.getOperandRefType(index)

    match = InstructionMatch(
        ins_addr, direction, ref_type, instruction)

    return match

def find_instruction_matches(function, target):
    """
    Find instructions that contain the target value.
    
    :param function: Function to search.
    :param target: Target to search for in each operation.
    
    :returns: List of instruction matches.
    """
    instruction_matches = []
    function_instructions = get_instruction_list(function) 
    for instruction in function_instructions:
        # Labels don't show up so check the flow, if its a call see if it
        # contains the target.
        if check_flows(instruction, target):
            match = create_match(instruction)
            instruction_matches.append(match)
            continue

        # Check each operand of the instruction for the target.
        operand_count = instruction.getNumOperands() 
        for index in range(0, operand_count):
            operand = instruction.getDefaultOperandRepresentation(index)
            if target in operand:
                match = create_match(instruction, index)
                instruction_matches.append(match)
                break

    return instruction_matches


function = get_function(currentLocation.address)
selection = get_selection(function)
matches = find_instruction_matches(function, selection)

# If no matches were found search again using the raw address of the selection.
if not matches:
    print 'No matches found for %s, searching again with the raw address.' % \
        selection
    selection = get_selection(function, True)
    matches = find_instruction_matches(function, selection)

if matches:

    for match in matches:
        print match
else:
    print 'No matches found for {} in {}.'.format(selection, function)