import re
from ghidra.program.flatapi import FlatProgramAPI


format_string = '| {:12} | {:12} | {:30} | {:12} | {:30} |'
format_double_string = '| {:12} | {:30} | {:12} | {:30} | {:12} | {:30} | {:12} | {:30} |'
summary_format = '| {:15} | {:14} | {:30} |'


class MipsInstruction(object):
    """
    Class to represent a MIPS Instruction.
    """

    def __init__(self, mnem, op1=None, op2=None, op3=None):
        self.mnem = mnem
        self.op1 = op1
        self.op2 = op2
        self.op3 = op3


class MipsRop(object):
    def __init__(self, program):
        self._flat_api = FlatProgramAPI(program)
        self._currentProgram = program
        self.controllable_calls = []
        self.controllable_terminating_calls = []
        self._find_controllable_calls()

    def find_instructions(self, instructions, preserve_register=None,
                          controllable_calls=True, terminating_calls=True):
        """
        Search for gadgets that contain user defined instructions.
        """
        gadgets = RopGadgets()

        search_calls = []
        if controllable_calls:
            search_calls.extend(self.controllable_calls)
        if terminating_calls:
            search_calls.extend(self.controllable_terminating_calls)

        for call in search_calls:
            rop = self._find_instruction(call, instructions, preserve_register)
            if rop:
                gadgets.append(RopGadget(rop, call))

        return gadgets

    def find_doubles(self):
        """
        Find double jumps.

        :returns: List of double jump gadgets.
        :rtype: DoubleGadgets
        """
        controllable = self.controllable_calls + \
            self.controllable_terminating_calls

        gadgets = DoubleGadgets()
        for i, call in enumerate(controllable):
            for j in range(i + 1, len(controllable)):
                second_call = controllable[j]
                second_call_addr = second_call.control_instruction.getAddress()
                distance = second_call_addr.subtract(call.call.getAddress())

                # Search for a distance of no more than 25 instructions.
                if 0 < distance <= 100:
                    # If the jumps are in different functions do not return
                    # them
                    func1 = self._flat_api.getFunctionContaining(
                        second_call.call.getAddress())
                    func2 = self._flat_api.getFunctionContaining(
                        call.call.getAddress())
                    if func1 != func2:
                        continue

                    if call.get_source_register() == \
                            second_call.get_source_register():
                        continue

                    if not self._contains_bad_calls(call, second_call):
                        gadgets.append(DoubleGadget(call, second_call))

        return gadgets

    def summary(self):
        """
        Search for bookmarks that start with 'rop' and print a summary of the 
        ROP gadgets. Case of 'rop' is not important. 
        """
        bookmark_manager = self._currentProgram.getBookmarkManager()
        bookmarks = bookmark_manager.getBookmarksIterator()

        saved_rops = []

        for bookmark in bookmarks:
            comment = bookmark.getComment().lower()
            if comment.startswith('rop'):
                for saved in saved_rops:
                    if saved.getComment().lower() == comment:
                        print 'Duplicate bookmark found: {} at {} and {}'.format(
                            comment, saved.getAddress(), bookmark.getAddress())
                        return
                saved_rops.append(bookmark)

        saved_rops = sorted(saved_rops, key=lambda x: x.comment.lower())

        rop_gadgets = RopGadgets()
        for rop in saved_rops:
            closest_jmp = self._find_closest_controllable_jump(
                rop.getAddress())
            if closest_jmp:
                curr_addr = rop.getAddress()
                curr_ins = self._flat_api.getInstructionAt(curr_addr)
                rop_gadgets.append(RopGadget(curr_ins, closest_jmp,
                                             rop.getComment()))
        rop_gadgets.print_summary()

    def _find_closest_controllable_jump(self, address):
        """
        Find closest controllable jump to the address provided.

        :param address: Address to find closest jump to.
        :type address: ghidra.program.model.address.Address

        :returns: Closest controllable jump, if it exists.
        :rtype: ControllableCall or None
        """
        controllable = self.controllable_calls + \
            self.controllable_terminating_calls

        function = self._flat_api.getFunctionContaining(address)

        closest = None

        for jump in controllable[1:]:
            jump_function = self._flat_api.getFunctionContaining(
                jump.call.getAddress())
            if function != jump_function:
                continue

            if address > jump.control_instruction.getAddress():
                continue

            if not closest or \
                    jump.control_instruction.getAddress() <= \
                    address <= jump.call.getAddress():
                closest = jump
            else:
                control_addr = jump.control_instruction.getAddress()
                closest_distances = closest.control_instruction.getAddress()
                if control_addr.subtract(closest_distances) > \
                        control_addr.subtract(address):
                    closest = jump
        return closest

    def _find_controllable_calls(self):
        """
        Find calls that can be controlled through saved registers.
        """
        program_base = self._currentProgram.getImageBase()

        code_manager = self._currentProgram.getCodeManager()
        instructions = code_manager.getInstructions(program_base, True)

        # Loop through each instruction in the current program.
        for ins in instructions:
            flow_type = ins.getFlowType()

            # jalr t9 and some jr t9 are isCall()
            # jr ra is isTerminal()
            # some jr t9 are isJump() && isComputed().
            if flow_type.isCall() or flow_type.isTerminal() or \
                    (flow_type.isJump() and flow_type.isComputed()):
                current_instruction = self._flat_api.getInstructionAt(
                    ins.getAddress())
                controllable = self._find_controllable_call(
                    current_instruction)

                # Sort the controllable jump by type. Makes finding indirect
                # function calls easier.
                if controllable:
                    if flow_type.isCall() and not flow_type.isTerminal():
                        self.controllable_calls.append(controllable)
                    elif flow_type.isTerminal() or \
                            (flow_type.isJump() and flow_type.isComputed()):
                        self.controllable_terminating_calls.append(
                            controllable)

    def _find_controllable_call(self, call_instruction):
        """
        Search for how the jump register is set. If it comes from a potentially
        controllable register then return it.

        :param call_instruction: Instruction that contains a call.
        :type instruction: ghidra.program.mdel.listing.Instruction

        :returns: Controllable call object if controllable, None if not.
        :rtype: ControllableCall or None
        """
        t9_move = MipsInstruction('.*move', 't9', '[sva][012345678]')
        ra_load = MipsInstruction('.*lw', 'ra')

        call_from = call_instruction.getOpObjects(0)[0]

        # No need to check the delay slot so start working back up.
        controllable = None
        previous_ins = self._get_previous_instruction(call_instruction)

        while previous_ins:
            # NOPs are handled weirdly, they have no "flow" so just skip it.
            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()

            first_op = previous_ins.getOpObjects(0)
            if len(first_op):
                dest_reg = first_op[0]
                if str(dest_reg) == str(call_from):
                    if instruction_matches(previous_ins,
                                           [t9_move, ra_load]):
                        return ControllableCall(call_instruction, previous_ins)
                    return None

            previous_ins = self._get_previous_instruction(previous_ins)

    def _get_previous_instruction(self, instruction):
        """
        Get the previous instruction. Check the "flow" first, if not found
        just return the previous memory instruction.

        :param instruction: Instruction to retrieve previous instruction from.
        :type instruction: ghidra.program.model.listing.Instruction
        """
        fall_from = instruction.getFallFrom()
        if fall_from is None:
            previous_ins = instruction.getPrevious()
        else:
            previous_ins = self._flat_api.getInstructionAt(fall_from)

        return previous_ins

    def _find_instruction(self, controllable_call, search_instructions,
                          preserve_reg=None):
        """
        Search for an instruction within a controllable call. 

        :param controllable_call: Controllable call to search within.
        :type controllable_call: ControllableCall

        :param search_instructions: Instruction list to search for.
        :type search_instructions: list(MipsInstruction)

        :param preserve_reg: Register to preserve, if overwritten the 
                             instruction will not be returned.
        :type preserve_reg: str

        :returns: The matching instruction if found, None otherwise.
        :rtype: ghidra.program.model.listing.Instruction
        """
        delay_slot = controllable_call.call.getNext()
        if instruction_matches(delay_slot, search_instructions):
            return delay_slot

        previous_ins = self._get_previous_instruction(controllable_call.call)

        while previous_ins:
            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()

            if instruction_matches(previous_ins, search_instructions):
                return previous_ins

            if preserve_reg and \
                    register_overwritten(previous_ins, preserve_reg):
                return None

            # TODO: Need to see if we passed the point of caring.
            if register_overwritten(previous_ins,
                                    controllable_call.control_instruction):
                return None

            if is_jump(previous_ins):
                return check_delay_slot(previous_ins, search_instructions)

            previous_ins = self._get_previous_instruction(previous_ins)

        return None

    def _contains_bad_calls(self, first, second):
        """
        Search for bad calls between two controllable jumps.

        :param first: Controllable call that comes first in memory.
        :type first: ControllableCall

        :param second: Controllable call that comes second in memory.
        :type second ControllableCall

        :returns: True if bad calls are found, False otherwise.
        :rtype: bool
        """
        jump = MipsInstruction('j.*')
        branch = MipsInstruction('b.*')

        preserve_reg = str(second.control_instruction.getOpObjects(1)[-1])
        end_ins = first.call

        previous_ins = self._get_previous_instruction(
            second.control_instruction)

        while previous_ins.getAddress() > end_ins.getAddress():
            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()

            if instruction_matches(previous_ins, [jump, branch]):
                return True

            if register_overwritten(previous_ins, preserve_reg):
                return True

            previous_ins = self._get_previous_instruction(previous_ins)

        return False


class ControllableCall(object):
    """
    Class to store controllable calls and the instruction that controls it.
    """

    def __init__(self, instruction, control_instruction):
        self.call = instruction
        self.control_instruction = control_instruction

    def get_source_register(self):
        """
        Get the controlling source register.
        """
        try:
            return str(self.control_instruction.getOpObjects(1)[-1])
        except:
            return None

    def get_control_item(self):
        """
        Get string source of the control item. 
        """
        return self.control_instruction.getDefaultOperandRepresentation(1)

    def control_jump(self):
        """
        Return string representing the jump. Instead of 'jalr t9' it might 
        return 'jalr s4' to represent the controlling register.
        """
        return '{:10} {}'.format(self.call.getMnemonicString(),
                                 self.get_control_item())

    def __str__(self):
        return '{} {} -> {} {}'.format(self.control_instruction.getAddress(),
                                       self.control_instruction,
                                       self.call.getAddress(),
                                       self.call)


class RopGadget(object):
    """
    Class to represent discovered gadgets.
    """

    def __init__(self, action, jump, name=None):
        self.action = action
        self.jump = jump
        self.name = name

    def __str__(self):
        control_addr = self.jump.control_instruction.getAddress()
        action_addr = self.action.getAddress()

        start = self.jump.control_instruction \
            if control_addr < action_addr else self.action

        return format_string.format(start.getAddress(),
                                    self.action.getAddress(),
                                    self.action,
                                    self.jump.call.getAddress(),
                                    self.jump.control_jump())

    def get_instructions(self):
        """
        Get a list of instructions between the first instruction in the rop
        and the call.
        """
        instructions = []

        # Find the higher call, the action or the control instruction.
        start_ins = self.action if self.action.getAddress() \
            < self.jump.control_instruction.getAddress() else \
            self.jump.control_instruction

        instructions.append(start_ins)
        curr_ins = start_ins
        while curr_ins.getAddress() <= self.jump.call.getAddress():
            curr_ins = curr_ins.getNext()
            instructions.append(curr_ins)

        return instructions


class RopGadgets(object):
    """
    Class to contain discovered gadgets.
    """

    def __init__(self):
        self.gadgets = []

    def append(self, gadget):
        """
        Add a gadget to the list.
        """
        self.gadgets.append(gadget)

    def pretty_print(self):
        """
        Print the gadgets in a nice table.
        """
        if len(self.gadgets):
            line_len = len(str(self.gadgets[0]))
            print '-' * line_len
            print format_string.format(
                'Gadget Start', 'Action Addr', 'Action', 'Jump Addr', 'Jump')
            print '-' * line_len
            for gadget in self.gadgets:
                print gadget
            print '-' * line_len
        print 'Found {} matching gadgets.\n'.format(len(self.gadgets))

    def print_summary(self):
        """
        Print ROP chain summary.
        """
        if len(self.gadgets):
            title = summary_format.format(
                'Gadget Name', 'Gadget Offset', 'Summary')
            line_len = len(title)
            print '-' * line_len
            print title
            print '-' * line_len
            for gadget in self.gadgets:
                instructions = gadget.get_instructions()
                print summary_format.format(gadget.name,
                                            instructions[0].getAddress(),
                                            instructions[0])
                for instruction in instructions[1:]:
                    print summary_format.format('', '', instruction)
                print '-' * line_len
        else:
            print 'No bookmarks with "rop" found.'


class DoubleGadget(object):
    """
    Class to contain double jump gadget.
    """

    def __init__(self, first, second):
        self.first = first
        self.second = second

    def __str__(self):
        return format_double_string.format(
            self.first.control_instruction.getAddress(),
            self.first.control_instruction,
            self.first.call.getAddress(), self.first.control_jump(),
            self.second.control_instruction.getAddress(),
            self.second.control_instruction,
            self.second.call.getAddress(),
            self.second.control_jump())


class DoubleGadgets(RopGadgets):
    """
    Class to contain double jump gadget.
    """

    def __init__(self):
        self.gadgets = []
        super(DoubleGadgets, self).__init__()

    def pretty_print(self):
        """
        Print gadgets in a nice table.
        """
        if len(self.gadgets):
            line_len = len(str(self.gadgets[0]))
            print '-' * line_len
            print format_double_string.format(
                'Gadget Start', '1st Action', 'Address', '1st Jump', 'Address',
                '2nd Action', 'Address', '2nd Jump')
            print '-' * line_len
            for gadget in self.gadgets:
                print gadget
            print '-' * line_len
        print 'Found {} matching gadgets.\n'.format(len(self.gadgets))


def instruction_matches(ins, matches):
    """
    Does instruction match any from a list of given instructions.

    :param ins: Instruction to compare.
    :type ins: ghidra.program.model.listing.Instruction

    :param matches: List of instructions to compare against. Regex supported.
    :type matches: list(MipsInstruction)

    :returns: True if an instruction match was found, False otherwise.
    :rtype: bool
    """
    for match in matches:
        if not re.match(match.mnem, ins.getMnemonicString()):
            continue
        try:
            if match.op1 and \
                    not re.match(match.op1, str(ins.getOpObjects(0)[0])):
                continue

            if match.op2 and \
                    not re.match(match.op2, str(ins.getOpObjects(1)[0])):
                continue

            if match.op3 and \
                    not re.match(match.op3, str(ins.getOpObjects(2)[0])):
                continue
            return True
        except IndexErrors:
            continue
        return False


def register_overwritten(ins, register):
    """
    Check if a register is overwritten in an instruction.

    :param ins: Instruction to inspect.
    :type ins: ghidra.program.model.listing.Instruction

    :param register: Register to search for.
    :type register: str

    :returns: True if overwritten, False otherwise.
    :rtype: bool
    """
    objects = ins.getOpObjects(0)
    if objects and str(objects[0]) == register:
        return True
    return False


def is_jump(ins):
    """
    Is instruction a jump (or call).

    :param ins: Instruction to inspect.
    :type ins: ghidra.program.model.listing.Instruction

    :returns: True if instruction is a jump, False otherwise.
    """
    return ins.getFlowType().isCall() or ins.getFlowType().isJump()


def check_delay_slot(ins, matches):
    """
    Check delay slot of an instruction that matches the provided instructions. 

    :param ins: Instruction to inspect delay slot for.
    :type ins: ghidra.program.model.listing

    :param matches: List of instructions to search.
    :ins matches: list(MipsInstruction)
    """
    next_ins = ins.getNext()
    if instruction_matches(next_ins, matches):
        return next_ins
    return None
