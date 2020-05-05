# Build a ROP chain that can be used to call shellcode.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.ROP Chains.Shellcode

from utils import mipsropchain, mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')


def find_lia0_calls(rop_finder, vebose):
    """
    Find calls the load a value smaller than 16 into $a0.

    :param rop_finder: Mips rop finder class.
    :type rop_finder: mipsrop.MipsRop

    :returns: Gadgets found.
    :rtype: list(mipsrop.RopGadget)
    """
    li_a0 = mipsrop.MipsInstruction('.*li', 'a0', '0x[0-9a-f]')
    small_value = rop_finder.find_instructions([li_a0])
    if verbose:
        print 'Found %d gadgets to load a small value into a0' % \
            len(small_value.gadgets)
    return small_value.gadgets


def find_stack_finders(rop_finder, verbose):
    """
    Find gadgets that move a stack pointer to a register.

    :param rop_finder: Mips rop finder class.
    :type rop_finder: mipsrop.MipsRop

    :returns: Gadgets found.
    :rtype: list(mipsrop.RopGadget)
    """
    sf_saved_reg = mipsrop.MipsInstruction('.*addiu', '[sva][012345678]', 'sp')
    stack_finder_gadgets = rop_finder.find_instructions(
        [sf_saved_reg], terminating_calls=False)
    if verbose:
        print 'Found %d gadgets to find shellcode on the stack.' % \
            len(stack_finder_gadgets.gadgets)
    return stack_finder_gadgets.gadgets


def find_double_jumps(rop_finder, allow_double=True, allow_iret=True,
                      verbose=False):
    """
    Find gadgets that call a function and maintain control to jump to the next
    gadget.

    :param rop_finder: Mips rop finder class.
    :type rop_finder: mipsrop.MipsRop

    :returns: Gadgets found.
    :rtype: list(mipsrop.RopGadget + mipsrop.DoubleGadget)
    """
    gadgets = []
    if allow_double:
        doubles = rop_finder.find_doubles()
        gadgets.extend(doubles.gadgets)
    if allow_iret:
        move_t9 = mipsrop.MipsInstruction('move', 't9', '[sav][012345678]')
        irets = rop_finder.find_instructions(
            [move_t9], controllable_calls=False, overwrite_register=['ra'])
        gadgets.extend(irets.gadgets)
    if verbose:
        print 'Found %d gadgets to call sleep and maintain control' % len(gadgets)
    return gadgets


def custom_shellcode_find(link, controlled_registers, curr_chain):
    """
    Custom find to search for gadgets that call a register based on where
    the previous gadget stored it.
    """
    shell_code_location = curr_chain[-1].get_action_destination()[0]
    for jump in link.jump_register:
        if jump != shell_code_location:
            return False
    return True


def find_shellcode_jump(rop_finder, verbose):
    """
    Find gadgets that call a register.

    :param rop_finder: Mips rop finder class.
    :type rop_finder: mipsrop.MipsRop

    :returns: Gadgets found.
    :rtype: list(mipsrop.RopGadget)
    """
    move_t9 = mipsrop.MipsInstruction('mov', 't9')
    call_register = rop_finder.find_instructions(
        [move_t9])
    if verbose:
        print 'Found %d gadgets to call shellcode.' % len(call_register.gadgets)
    return call_register.gadgets


def find_epilogue(rop_finder, controlled_registers):
    """
    Find epilogues that grant control of each register. Will only return 
    epilogues that grant control over more registers than originally used.

    :param rop_finder: Mips rop finder class.
    :type rop_finder: mipsrop.MipsRop

    :param controlled_registers: Registers controlled.
    :type controlled_registers: list(str)

    :returns: Gadgets found.
    :rtype: list(mipsrop.RopGadgets)
    """
    epilogue = mipsrop.MipsInstruction('.*lw', 'ra')
    function_epilogue = []

    for i in range(0, len(mipsropchain.REGISTERS)):
        control_registers = mipsropchain.REGISTERS[:i + 1]
        if all(reg in controlled_registers for reg in control_registers):
            continue
        epilogue_gadget = rop_finder.find_instructions(
            [epilogue], controllable_calls=False,
            overwrite_register=control_registers,
            preserve_register=mipsropchain.REGISTERS[i + 1:])
        if epilogue_gadget.gadgets:
            function_epilogue.append(epilogue_gadget.gadgets[0])
    return function_epilogue


mips_rop = mipsrop.MipsRop(currentProgram)

# User request for currently controlled registers.
registers_controlled = askChoices(
    'Registers Controlled', 'Which registers do you control, excluding ra?',
    ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8'])

# User request for how many chains they want returned.
chain_count = askInt('Chains', 'How many chains to you want to find?')

# User request for special options.
special_options = askChoices(
    'Options', 'Any special requests?',
    ['iret', 'double', 'control', 'reuse', 'verbose'],
    ['Avoid indirect returns', 'Avoid double jumps',
     'Avoid gadgets that require a control jump.', 'Do not reuse gadgets.',
     'Verbose output.'])
allow_control = 'control' not in special_options
allow_reuse = 'reuse' not in special_options
allow_double = 'double' not in special_options
allow_iret = 'iret' not in special_options
verbose = 'verbose' in special_options

if verbose:
    print 'You control registers: %s' % ', '.join(registers_controlled)
    print 'Searching for required gadgets...'

# Find all required gadgets.
lia0 = find_lia0_calls(mips_rop, verbose)
stack_finders = find_stack_finders(mips_rop, verbose)
doubles = find_double_jumps(mips_rop, allow_double, allow_iret, verbose)
shellcode = find_shellcode_jump(mips_rop, verbose)

# Set up the chain build with the order the gadgets should be called.
chain_builder = mipsropchain.ChainBuilder(mips_rop, registers_controlled,
                                          chain_count, allow_reuse, verbose)
chain_builder.add_gadgets('Load Immediate to a0', lia0, allow_control)
chain_builder.add_gadgets('Call sleep and maintain control', doubles,
                          allow_control)
chain_builder.add_gadgets('Shellcode finder', stack_finders, allow_control)
chain_builder.add_gadgets('Call shellcode', shellcode,
                          False, find_fn=custom_shellcode_find)
chain_builder.generate_chain()

# If no chains were found or not enough add epilogues and keep searching.
if not chain_builder.chains or len(chain_builder.chains) < chain_count:
    if verbose:
        print 'Adding epilogues to control more registers.'
    epilogues = find_epilogue(mips_rop, registers_controlled)
    chain_builder.add_gadgets('Control More Registers', epilogues,
                              check_control=False, index=0)
    chain_builder.generate_chain()

print 'Found %d chains' % len(chain_builder.chains)

chain_builder.display_chains(verbose)
