# Build a ROP chain that can be used to call system with a controllable command.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.ROP Chains.System

from utils import mipsropchain, mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')


def find_system_calls(rop_finder, terminating, controllable, verbose):
    """
    Find single gadget chains to call system with a controllable string in
    a0.

    :param rop_finder: MIPS rop finder class.
    :type rop_finder: mipsrop.MipsRop

    :param terminating: Return tail gadgets.
    :type terminating: bool

    :param controllable: Return controllable calls.
    :type controllable: bool

    :param verbose: Enable verbose output.
    :type verbose: bool

    :returns: Discovered gadgets
    :rtype: list(mipsrop.RopGadgets)
    """
    system_call = mipsrop.MipsInstruction('.*addiu', 'a0', 'sp')
    stack_finders = rop_finder.find_instructions(
        [system_call], terminating_calls=terminating,
        controllable_calls=controllable)
    if verbose:
        print 'Found %d gadgets to call system.' % \
            len(stack_finders.gadgets)
    return stack_finders.gadgets


def find_stack_finders(rop_finder, terminating, controllable, verbose):
    """
    Find gadgets that move a stack pointer to a register. Movement to a0 is
    specifically ignored because the system gadget finder does that.

    :param rop_finder: Mips rop finder class.
    :type rop_finder: mipsrop.MipsRop

    :param terminating: Return tail gadgets.
    :type terminating: bool

    :param controllable: Return controllable calls.
    :type controllable: bool

    :param verbose: Enable verbose output.
    :type verbose: bool

    :returns: Gadgets found.
    :rtype: list(mipsrop.RopGadget)
    """
    sf_saved_reg = mipsrop.MipsInstruction(
        '.*addiu', '[sva][012345678]', 'sp')
    stack_finders = rop_finder.find_instructions(
        [sf_saved_reg], terminating_calls=terminating,
        controllable_calls=controllable)
    if verbose:
        print 'Found %d gadgets to find shellcode on the stack.' % \
            len(stack_finders.gadgets)
    return stack_finders.gadgets


def find_move_a0(rop_finder, verbose):
    """
    Find gadget that moves a register to a0.

    :param rop_finder: MIPS rop finder class.
    :type rop_finder: mipsrop.MipsRop

    :param verbose: Enable verbose output.
    :type verbose: bool

    :returns: Discovered gadgets
    :rtype: list(mipsrop.RopGadgets)
    """
    move_a0_ins = mipsrop.MipsInstruction('.*move', 'a0', '[sva][012345678]')
    # System cannot be called from an epilogue. $gp is calculated based on the
    # call occurring from $t9.
    move_a0 = rop_finder.find_instructions([move_a0_ins],
                                           terminating_calls=False)
    if verbose:
        print 'Found %d gadgets to move a register to $a0.' % \
            len(move_a0.gadgets)
    return move_a0.gadgets


def find_epilogue(rop_finder, controlled_registers):
    """
    Find epilogues that grant control of each register. Ideal will return nine
    gadgets one that gives control of s0, one that gives control of s0 and s1,
    one that gives control of s0/s1/s2, etc.

    :param rop_finder: Mips rop finder class.
    :type rop_finder: mipsrop.MipsRop

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


def system_single_simple_jump(chain_builder, mips_rop):
    """
    Find traditional system gadgets that move a stack string to a0 then call
    a controllable register. Applied gadgets will be cleared from the chain
    builder when the function is complete.

    :param chain_builder: Initialized chain builder class.
    :type chain_builder: mipsropchain.ChainBuilder

    :param mips_rop: Mips rop finder class.
    :type mips_rop: mipsrop.MipsRop
    """
    system_calls = find_system_calls(mips_rop, False, True, verbose)
    chain_builder.add_gadgets('Call system.', system_calls)

    chain_builder.generate_chain()
    chain_builder.gadgets = []


def single_system_custom_find(link, controlled_registers, current_chain):
    """
    Custom find command that searches for a single gadget that moves a stack
    pointer to a register and moves that resister to a0.

    :param link: Current link to process.
    :type link: mipsropchain.ChainLink
    """
    if not mipsropchain.default_gadget_search(
            link, controlled_registers, current_chain):
        return False

    if 'a0' in link.overwritten:
        a0_ins = getInstructionAt(link.overwritten['a0'][0])
        a0_src = str(a0_ins.getOpObjects(1)[0])
        action_dest = link.get_action_destination()[0]
        if a0_src == action_dest and \
                link.overwritten['a0'] > link.overwritten[action_dest]:
            return True
    return False


def system_single_extended_jump(chain_builder, mips_rop):
    """
    Find extended single gadgets that move a stack string to a registers and 
    then move that register to a0. A custom find function is used to support
    this search.

    :param chain_builder: Initialized chain builder class.
    :type chain_builder: mipsropchain.ChainBuilder

    :param mips_rop: Mips rop finder class.
    :type mips_rop: mipsrop.MipsRop
    """
    stack_finders = find_stack_finders(mips_rop, False, True, verbose)
    chain_builder.add_gadgets('Find command on the stack', stack_finders,
                              find_fn=single_system_custom_find)
    chain_builder.generate_chain()
    chain_builder.gadgets = []


def system_tail_two_jump(chain_builder, mips_rop):
    """
    Search for chain that moves a stack string to a0 in a tail call.

    :param chain_builder: Initialized chain builder class.
    :type chain_builder: mipsropchain.ChainBuilder

    :param mips_rop: Mips rop finder class.
    :type mips_rop: mipsrop.MipsRop
    """
    stack_finders = find_system_calls(mips_rop, True, False, verbose)
    chain_builder.add_gadgets(
        'Find command on the stack from tail call', stack_finders)

    move_t9 = mipsrop.MipsInstruction('mov', 't9')
    call_register = mips_rop.find_instructions(
        [move_t9], preserve_register='a0', terminating_calls=False)
    chain_builder.add_gadgets('Call system.', call_register.gadgets)
    chain_builder.generate_chain()
    chain_builder.gadgets = []


def system_two_jump_custom_find(link, controlled_registers, current_chain):
    """
    Custom find to search for gadget that moves a register from a previous 
    jump to a0.
    """
    if not mipsropchain.default_gadget_search(
            link, controlled_registers, current_chain):
        return False

    actions = link.get_action_source()
    last_link_actions = current_chain[-1].get_action_destination()
    for action in last_link_actions:
        if action not in actions:
            return False
    return True


def system_two_jump(chain_builder, mips_rop):
    """
    Find chains that move a stack string to a register and move that register
    to a0 in the next gadget.

    :param chain_builder: Initialized chain builder class.
    :type chain_builder: mipsropchain.ChainBuilder

    :param mips_rop: Mips rop finder class.
    :type mips_rop: mipsrop.MipsRop
    """
    stack_finders = find_stack_finders(mips_rop, False, True, verbose)
    chain_builder.add_gadgets('Find command on the stack', stack_finders)

    move_a0 = find_move_a0(mips_rop, verbose)
    chain_builder.add_gadgets(
        'Move command to $a0', move_a0, find_fn=system_two_jump_custom_find)
    chain_builder.generate_chain()
    chain_builder.gadgets = []


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
    ['control', 'reuse', 'verbose'],
    ['Avoid gadgets that require a control jump.', 'Do not reuse gadgets.',
     'Verbose output.'])
allow_control = 'control' not in special_options
allow_reuse = 'reuse' not in special_options
verbose = 'verbose' in special_options

if verbose:
    print 'You control registers: %s' % ', '.join(registers_controlled)
    print 'Searching for required gadgets...'

chain_builder = mipsropchain.ChainBuilder(mips_rop, registers_controlled,
                                          chain_count, allow_reuse, verbose)

system_single_simple_jump(chain_builder, mips_rop)
system_single_extended_jump(chain_builder, mips_rop)
system_two_jump(chain_builder, mips_rop)
system_tail_two_jump(chain_builder, mips_rop)

# If no chains were found or not enough add epilogues and keep searching.
if not chain_builder.chains or len(chain_builder.chains) < chain_count:
    if verbose:
        print 'Adding epilogues to control more registers.'
#
    epilogues = find_epilogue(mips_rop, registers_controlled)
    for system_find in [system_single_simple_jump, system_single_extended_jump,
                        system_two_jump, system_tail_two_jump]:
        chain_builder.add_gadgets('Control More Registers', epilogues,
                                  check_control=False)

        system_find(chain_builder, mips_rop)

print 'Found %d chains' % len(chain_builder.chains)

chain_builder.display_chains(verbose)
