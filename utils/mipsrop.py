import re
from ghidra.program.flatapi import FlatProgramAPI


format_string = '| {:12} | {:12} | {:30} | {:12} | {:30} |'


class ControllableCall(object):
    def __init__(self, instruction, control_instruction):
        self.call = instruction
        self.control_instruction = control_instruction

    def get_control_item(self):
        return self.control_instruction.getDefaultOperandRepresentation(1)

    def control_jump(self):
        return '{:10} {}'.format(self.call.getMnemonicString(),
                                 self.get_control_item())


class RopGadget(object):
    def __init__(self, action, jump):
        self.action = action
        self.jump = jump

    def __str__(self):

        control_addr = self.jump.control_instruction.getAddress()
        action_addr = self.action.getAddress()

        start = self.jump.control_instruction if control_addr < action_addr else self.action

        return format_string.format(start.getAddress(),
                                    self.action.getAddress(),
                                    self.action,
                                    self.jump.call.getAddress(),
                                    self.jump.control_jump())


class RopGadgets(object):
    def __init__(self):
        self.gadgets = []

    def append(self, gadget):
        self.gadgets.append(gadget)

    def pretty_print(self):
        if len(self.gadgets):
            line_len = len(str(self.gadgets[0]))
            print '-' * line_len
            print format_string.format('Gadget Start', 'Action Addr', 'Action', 'Jump Addr', 'Jump')
            print '-' * line_len
            for gadget in self.gadgets:
                print gadget
            print '-' * line_len
        print 'Found {} matching gadgets.\n'.format(len(self.gadgets))


class MipsInstruction(object):
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

    def find_controllable_calls(self):
        """
        Find calls that can be controlled through saved registers.
        """
        program_base = self._currentProgram.getImageBase()

        code_manager = self._currentProgram.getCodeManager()
        instructions = code_manager.getInstructions(program_base, True)

        for ins in instructions:
            flow_type = ins.getFlowType()

            if flow_type.isCall() or flow_type.isTerminal() or \
                    (flow_type.isJump() and flow_type.isComputed()):
                current_instruction = self._flat_api.getInstructionAt(
                    ins.getAddress())
                controllable = self._find_controllable_call(
                    current_instruction)

                if controllable:
                    if flow_type.isCall() and not flow_type.isTerminal():
                        self.controllable_calls.append(controllable)
                    elif flow_type.isTerminal() or \
                            (flow_type.isJump() and flow_type.isComputed()):
                        self.controllable_terminating_calls.append(
                            controllable)

    def _find_controllable_call(self, call_instruction):
        t9_move = MipsInstruction('move', 't9', '[sva][012345678]')
        ra_load = MipsInstruction('.*lw', 'ra')

        call_from = call_instruction.getOpObjects(0)[0]

        controllable = None
        fall_from = call_instruction.getFallFrom()
        if fall_from is None:
            previous_ins = call_instruction.getPrevious()
        else:
            previous_ins = self._flat_api.getInstructionAt(fall_from)

        while previous_ins:
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

            fall_from = previous_ins.getFallFrom()
            if fall_from is None:
                previous_ins = previous_ins.getPrevious()
            else:
                previous_ins = self._flat_api.getInstructionAt(fall_from)

    def find_instructions(self, instructions, preserve_register=None,
                          controllable_calls=True, terminating_calls=True):
        gadgets = RopGadgets()

        search_calls = []
        if controllable_calls:
            search_calls.extend(self.controllable_calls)
        if terminating_calls:
            search_calls.extend(self.controllable_terminating_calls)

        for call in search_calls:
            rop = self._find_rop(call, instructions, preserve_register)
            if rop:
                gadgets.append(RopGadget(rop, call))

        return gadgets

    def _find_rop(self, controllable_call, search_instructions,
                  preserve_reg=None):
        delay_slot = controllable_call.call.getNext()
        if instruction_matches(delay_slot, search_instructions):
            return delay_slot

        fall_from = controllable_call.call.getFallFrom()
        if fall_from is None:
            previous_ins = controllable_call.call.getPrevious()
        else:
            previous_ins = self._flat_api.getInstructionAt(fall_from)

        while previous_ins:
            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()

            if instruction_matches(previous_ins, search_instructions):
                return previous_ins

            if preserve_reg and \
                    register_overwritten(previous_ins, preserve_reg):
                return None

            # Need to see if we passed the point of caring.
            if register_overwritten(previous_ins,
                                    controllable_call.control_instruction):
                return None

            if is_jump(previous_ins):
                return check_delay_slot(previous_ins, search_instructions,
                                        preserve_reg)

            fall_from = previous_ins.getFallFrom()
            if fall_from is None:
                previous_ins = previous_ins.getPrevious()
            else:
                previous_ins = self._flat_api.getInstructionAt(fall_from)

        return None


def instruction_matches(ins, matches):
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
    objects = ins.getOpObjects(0)
    if objects and str(objects[0]) == register:
        return True
    return False


def is_jump(ins):
    return ins.getFlowType().isCall() or ins.getFlowType().isJump()


def check_delay_slot(ins, match, preserve_reg):
    next_ins = ins.getNext()
    if instruction_matches(next_ins, match):
        return next_ins
    if preserve_reg and register_overwritten(next_ins, preserve_reg):
        return None
    return None
