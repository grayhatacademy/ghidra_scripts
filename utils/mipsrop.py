from ghidra.program.flatapi import FlatProgramAPI


format_string = '| {:12} | {:30} | {:30} |'


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
        return format_string.format(self.action.getAddress(),
                                    self.action,
                                    self.jump)


class RopGadgets(object):
    def __init__(self):
        self.gadgets = []

    def append(self, gadget):
        self.gadgets.append(gadget)

    def pretty_print(self):
        line_len = len(str(self.gadgets[0]))
        print '-' * line_len
        print format_string.format('Address', 'Action', 'Control Jump')
        print '-' * line_len
        for gadget in self.gadgets:
            print gadget
        print '-' * line_len


class MipsInstruction(object):
    def __init__(self, mnem, op1, op2):
        self.mnem = mnem
        self.op1 = op1
        self.op2 = op2


class MipsRop(object):
    def __init__(self, program):
        self._flat_api = FlatProgramAPI(program)
        self._currentProgram = program
        self.controllable_calls = []

    def find_controllable_calls(self):
        """
        Find calls that can be controlled through saved registers.
        """
        program_base = self._currentProgram.getImageBase()

        code_manager = self._currentProgram.getCodeManager()
        instructions = code_manager.getInstructions(program_base, True)

        for ins in instructions:
            flow_type = ins.getFlowType()
            if flow_type.isCall() or flow_type.isTerminal():
                current_instruction = self._flat_api.getInstructionAt(
                    ins.getAddress())
                controllable = self._find_controllable_call(
                    current_instruction)
                if controllable:
                    self.controllable_calls.append(controllable)

    def _find_controllable_call(self, call_instruction):
        controllable = None
        fall_from = call_instruction.getFallFrom()
        if fall_from is None:
            return False
        previous_ins = self._flat_api.getInstructionAt(fall_from)
        while previous_ins:
            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()
            first_op = previous_ins.getOpObjects(0)
            if len(first_op):
                dest_reg = first_op[0]
                if str(dest_reg) == 't9' or str(dest_reg) == 'ra':
                    second_op = previous_ins.getOpObjects(1)
                    for operand in second_op:
                        if 's' in str(operand):
                            return ControllableCall(call_instruction, previous_ins)
                    return None
                fall_from = previous_ins.getFallFrom()
                if fall_from is None:
                    return None
                previous_ins = self._flat_api.getInstructionAt(fall_from)

            else:
                return None

    def find_system_rops(self):
        """
        Find controllable calls that can be used to jump to system.
        """
        gadgets = RopGadgets()
        for jump in self.controllable_calls:
            system_rop = self._find_system_rop(jump)
            if system_rop:
                gadgets.append(RopGadget(system_rop, jump.control_jump()))

        return gadgets

    def _find_system_rop(self, controllable_call):
        set_a0 = MipsInstruction('addiu', 'a0', 'sp')
        load_system = MipsInstruction('la', 't9', 'system')

        delay_slot = controllable_call.call.getNext()
        if instruction_matches(delay_slot, [set_a0]):
            return delay_slot

        fall_from = controllable_call.call.getFallFrom()
        if fall_from is None:
            return False

        previous_ins = self._flat_api.getInstructionAt(fall_from)
        while previous_ins:
            if 'nop' in str(previous_ins):
                previous_ins = previous_ins.getPrevious()

            if instruction_matches(previous_ins, [set_a0]):
                return previous_ins

            if register_overwritten(previous_ins, 'a0'):
                return None

            # Need to see if we passed the point of caring.
            if register_overwritten(previous_ins, controllable_call.control_instruction):
                return None

            if is_jump(previous_ins):
                return check_delay_slot(previous_ins, [set_a0])

            fall_from = previous_ins.getFallFrom()
            if fall_from is None:
                return None
            previous_ins = self._flat_api.getInstructionAt(fall_from)

        return None


def instruction_matches(ins, matches):
    for match in matches:
        if match.mnem not in ins.getMnemonicString():
            continue
        try:
            if str(ins.getOpObjects(0)[0]) != match.op1:
                continue
            if str(ins.getOpObjects(1)[0]) != match.op2:
                continue
            return True
        except IndexError as e:
            continue
    return False


def register_overwritten(ins, register):
    objects = ins.getOpObjects(0)
    if objects and str(objects[0]) == register:
        return True
    return False


def is_jump(ins):
    return ins.getFlowType().isCall()


def check_delay_slot(ins, match):
    next_ins = ins.getNext()
    if instruction_matches(next_ins, match):
        return next_ins
    if register_overwritten(next_ins, 'a0'):
        return None
    return None
