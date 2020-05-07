import re
from . import utils
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import DataRefType


format_string = '| {:12} | {:12} | {:30} | {:12} | {:30} |'
format_double_string = '| {:12} | {:30} | {:12} | {:30} | {:12} | {:30} | {:12} | {:30} |'
summary_format = '| {:15} | {:14} | {:30} |'


class ArmInstruction(object):
    """
    Class to represent an ARM Instruction.
    """

    def __init__(self, mnem, op1=None, op2=None, op3=None):
        self.mnem = mnem
        self.op1 = op1
        self.op2 = op2
        self.op3 = op3


class ArmRop(object):
    def __init__(self, program):
        self._flat_api = FlatProgramAPI(program)
        self._currentProgram = program
        self.controllable_calls = []
        self.controllable_terminating_calls = []
        self._find_controllable_calls()

    def find_instructions(self, instructions, preserve_register=None,
                          controllable_calls=True, terminating_calls=True,
                          overwrite_register=None):
        """
        Search for gadgets that contain user defined instructions.

        :param instructions: List of instructions to search for.
        :type instructions: list(MipsInstruction)

        :param preserve_register: Registers to preserve.
        :type preserve_register: str

        :param controllable_calls: Search within controllable jumps.
        :type controllable_calls: bool

        :param terminating_calls: Search within controllable function epilogues.
        :type terminating_calls: bool

        :param overwrite_register: Register to ensure is overwritten.
        :param overwrite_register: str

        :returns: List of rop gadgets that contain the provided instructions.
        :rtype: list(RopGadgets)
        """
        gadgets = RopGadgets()

        search_calls = []
        if controllable_calls:
            search_calls.extend(self.controllable_calls)
        if terminating_calls:
            search_calls.extend(self.controllable_terminating_calls)

        for call in search_calls:
            rop = self._find_instruction(
                call, instructions, preserve_register, overwrite_register)
            if rop and self._is_valid_action(call, rop):
                gadgets.append(RopGadget(rop, call))

        return gadgets

    def find_doubles(self):
        """
        Find double jumps.

        :returns: List of double jump gadgets.
        :rtype: DoubleGadgets
        """
        controllable = self.controllable_calls
        terminating = self.controllable_terminating_calls

        gadgets = DoubleGadgets()
        for call in controllable:
            for second_call in terminating:
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

                    if not self._contains_bad_calls(call, second_call):
                        gadgets.append(DoubleGadget(call, second_call))

        return gadgets

    def summary(self):
        """
        Search for book marks that start with 'rop' and print a summary of the 
        ROP gadgets. Case of 'rop' is not important. 
        """
        bookmark_manager = self._currentProgram.getBookmarkManager()
        bookmarks = bookmark_manager.getBookmarksIterator()

        saved_bookmarks = []

        for bookmark in bookmarks:
            comment = bookmark.getComment().lower()
            if comment.startswith('rop'):
                for saved in saved_bookmarks:
                    if saved.getComment().lower() == comment:
                        print 'Duplicate bookmark found: {} at {} and {}'.format(
                            comment, saved.getAddress(), bookmark.getAddress())
                        return
                saved_bookmarks.append(bookmark)

        saved_bookmarks = sorted(saved_bookmarks,
                                 key=lambda x: x.comment.lower())

        rop_gadgets = RopGadgets()

        # Go through each bookmark, find the closest controllable jump, and
        # create a gadget.
        for bookmark in saved_bookmarks:
            closest_jmp = self._find_closest_controllable_jump(
                bookmark.getAddress())

            if closest_jmp:
                curr_addr = bookmark.getAddress()
                curr_ins = self._flat_api.getInstructionAt(curr_addr)
                rop_gadgets.append(RopGadget(curr_ins, closest_jmp,
                                             bookmark.getComment()))
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

        for jump in controllable:
            jump_function = self._flat_api.getFunctionContaining(
                jump.call.getAddress())
            if function != jump_function:
                continue

            if address > jump.control_instruction.getAddress():
                continue

            if jump.call.getAddress() == address:
                return jump

            if not closest or \
                    jump.control_instruction.getAddress() <= \
                    address <= jump.call.getAddress():
                closest = jump
            else:
                control_addr = jump.control_instruction.getAddress()
                closest_distances = closest.control_instruction.getAddress()
                if control_addr.subtract(address) < \
                        closest_distances.subtract(address):
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
        branch_link = ArmInstruction('blx', '[r][0123456789]')
        branch_exchange = ArmInstruction('bx', '[r][0123456789]')
        end = ArmInstruction('ldmia', 'sp*')

        if instruction_matches(call_instruction, [branch_link, branch_exchange, end]):
            return ControllableCall(call_instruction, call_instruction)
        return None

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
                          preserve_reg=None, overwrite_reg=None):
        """
        Search for an instruction within a controllable call. 

        :param controllable_call: Controllable call to search within.
        :type controllable_call: ControllableCall

        :param search_instructions: Instruction list to search for.
        :type search_instructions: list(MipsInstruction)

        :param preserve_reg: Register to preserve, if overwritten the 
                             instruction will not be returned.
        :type preserve_reg: str

        :param overwrite_reg: Enforce a register was overwritten.
        :type overwrite_reg: str

        :returns: The matching instruction if found, None otherwise.
        :rtype: ghidra.program.model.listing.Instruction
        """
        overwritten = False

        if instruction_matches(controllable_call.call, search_instructions):
            return controllable_call.call

        previous_ins = self._get_previous_instruction(controllable_call.call)
        function = self._flat_api.getFunctionContaining(
            controllable_call.call.getAddress())

        while previous_ins:
            # Break if we hit a call or jump.
            if utils.is_call_instruction(previous_ins) or \
                    utils.is_jump_instruction(previous_ins):
                return None

            # Break if we entered a different function.
            if function != self._flat_api.getFunctionContaining(previous_ins.getAddress()):
                return None

            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()

            if instruction_matches(previous_ins, search_instructions):
                if overwrite_reg and not overwritten:
                    return None
                return previous_ins

            if preserve_reg and \
                    register_overwritten(previous_ins, preserve_reg):
                return None

            if overwrite_reg and register_overwritten(previous_ins,
                                                      overwrite_reg):
                overwritten = True

            # TODO: Need to see if we passed the point of caring.
            if register_overwritten(previous_ins,
                                    controllable_call.get_control_item()):
                return None

            previous_ins = self._get_previous_instruction(previous_ins)

        return None

    def _is_valid_action(self, controllable_call, action):
        """
        Determine if an action is valid for the controllable call. 

        :param controllable_call: Controllable call to search within.
        :type controllable_call: ControllableCall

        :param action: Action to validate.
        :type action: ghidra.program.model.listing.Instruction

        :returns: The matching instruction if found, None otherwise.
        :rtype: ghidra.program.model.listing.Instruction
        """
        if controllable_call.call == action:
            return True

        previous_ins = controllable_call.call
        preserve_reg = action.getOpObjects(0)
        if preserve_reg:
            preserve_reg = str(preserve_reg[0])

        while previous_ins and previous_ins != action:
            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()

            if register_overwritten(previous_ins, preserve_reg):
                return False

            previous_ins = self._get_previous_instruction(previous_ins)

        return True

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
        branch = ArmInstruction('b.*')

        end_ins = first.call

        previous_ins = self._get_previous_instruction(
            second.control_instruction)

        while previous_ins.getAddress() > end_ins.getAddress():
            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()

            if instruction_matches(previous_ins, [branch]):
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
        return self.control_instruction.getDefaultOperandRepresentation(0)

    def control_jump(self):
        """
#        Return string representing the jump. Instead of 'jalr t9' it might 
#        return 'jalr s4' to represent the controlling register.
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

        return format_string.format(start,
                                    self.action.getAddress(),
                                    self.action,
                                    self.jump.call.getAddress(),
                                    self.jump.control_jump())

    def get_start(self):
        control_addr = self.jump.control_instruction.getAddress()
        action_addr = self.action.getAddress()

        start = self.jump.control_instruction \
            if control_addr < action_addr else self.action

        if len(start.getBytes()) == 4:
            return start.getAddress()
        else:
            return '%s + 1 = %s' % (start.getAddress(), start.getAddress().add(1))

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
        while curr_ins.getAddress() < self.jump.call.getAddress():
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
        title = ['Gadget Start', 'Action Addr', 'Action', 'Jump Addr', 'Jump']
        gadgets = []
        for gadget in self.gadgets:
            start = gadget.get_start()
            data = [start, gadget.action.getAddress(),
                    gadget.action, gadget.jump.call.getAddress(),
                    gadget.jump.control_jump()]
            data = map(str, data)
            gadgets.append(data)

        if gadgets:
            utils.table_pretty_print(title, gadgets)
        print 'Found %d matching gadgets.' % len(gadgets)

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

    def __init__(self, first, second, name=None):
        self.first = first
        self.second = second
        self.name = name
        self.instructions = []

    def __str__(self):
        return format_double_string.format(
            self.first.control_instruction.getAddress(),
            self.first.control_instruction,
            self.first.call.getAddress(), self.first.control_jump(),
            self.second.control_instruction.getAddress(),
            self.second.control_instruction,
            self.second.call.getAddress(),
            self.second.control_jump())

    def __len__(self):
        return len(self.get_instructions())

    def print_instructions(self):
        """
        Print instructions in the gadget.
        """
        instruction_list = self.get_instructions()
        for instruction in instruction_list:
            print '%s : %s' % (instruction.getAddress(), instruction)

    def overwrites_register(self, register):
        """
        Determine if a register is overwritten in the gadget.

        :returns True if the register is overwritten, False otherwise.
        :rtype: bool
        """
        instruction_list = self.get_instructions()
        for instruction in instruction_list:
            if register_overwritten(instruction, register):
                return True
        return False

    def get_instructions(self):
        """
        Get a list of instructions between the first instruction in the rop
        and the call.
        """
        if self.instructions:
            return self.instructions

        # Find the higher call, the action or the control instruction.
        start_ins = self.first.control_instruction if self.first.control_instruction.getAddress() \
            < self.first.call.getAddress() else self.first.call

        self.instructions.append(start_ins)
        curr_ins = start_ins
        while curr_ins.getAddress() <= self.second.call.getAddress():
            curr_ins = curr_ins.getNext()
            self.instructions.append(curr_ins)

        return self.instructions

    def get_action_destination_register(self):
        """
        Get the action destination register.

        :returns: Destination register as a list of strings.
        :rtype: list(str)
        """
        dest = []
        try:
            dest.append(str(self.first.control_instruction.getOpObjects(0)[0]))
            dest.append(
                str(self.second.control_instruction.getOpObjects(0)[0]))
        except:
            return []
        return dest

    def get_action_source_register(self):
        """
        Get the action source register.

        :returns: Source registers as a list of strings.
        :rtype: list(str)
        """
        src = []
        try:
            src.append(str(self.first.control_instruction.getOpObjects(1)[0]))
            src.append(str(self.second.control_instruction.getOpObjects(1)[0]))
        except:
            return []
        return src


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
        gadgets = []
        if len(self.gadgets):
            title = ['1st Jump', 'Address', '2nd Jump', 'Address']
            for gadget in self.gadgets:
                gadgets.append([
                    str(gadget.first.call.getAddress()
                        ), gadget.first.control_jump(),
                    str(gadget.second.call.getAddress()), gadget.second.control_jump()])
            utils.table_pretty_print(title, gadgets)

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
            _, ops = str(ins).split(' ', 1)
            if match.op1:
                if ',' in ops:
                    first_op, ops = ops.split(',', 1)
                else:
                    first_op = ops
                if not re.match(match.op1, first_op.strip()):
                    continue

                if match.op2:
                    if ',' in ops:
                        second_op, ops = ops.split(',', 1)
                    else:
                        second_op = ops
                    if not re.match(match.op2, second_op.strip()):
                        continue

                    if match.op3 and \
                            not re.match(match.op3, ops.strip()):
                        continue
            return True
        except ValueError as e:
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
    ref_type = ins.getOperandRefType(0)
    if objects and str(objects[0]) == register:
        if ref_type and ref_type in [DataRefType.WRITE, DataRefType.READ_WRITE]:
            return True
    elif not ref_type:
        # Some ldmia do not report operand ref type so see if the register
        # in question appears in the results objects.
        result_objects = ins.getResultObjects()
        results = [str(result) for result in result_objects]
        if register in results:
            return True
    return False
