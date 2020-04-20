# Find calls to a function and display source of parameters.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Operator

from utils import utils

from ghidra.program.model.symbol import RefType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.block import BasicBlockModel
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI


def get_argument_registers():
    """
    Get argument registers based on programs processor.
    """
    arch = utils.get_processor(currentProgram)

    if arch == 'MIPS':
        return ['a0', 'a1', 'a2', 'a3']
    elif arch == 'ARM':
        return ['r0', 'r1', 'r2', 'r3']
    return []


def get_return_registers():
    """
    Get return registers for the current processor.

    :returns: List of return registers.
    :rtype: list(str)
    """
    arch = utils.get_processor(currentProgram)

    if arch == 'MIPS':
        return ['v0', 'v1']
    elif arch == 'ARM':
        return ['r0']
    return []


def get_destination(instruction):
    """
    Find destination register for the current instruction.

    :param instruction: Instruction to find destination register for.
    :type instruction: ghidra.program.model.listing.Instruction

    :returns: List of destination registers if found, empty list if not found.
    :rtype: list(str)
    """
    if not instruction:
        return None

    result = instruction.getResultObjects()
    if not result:
        return []
    return [res.toString() for res in result]


def find_call(address):
    """
    Find the first call above the address provided taking into account if
    the address is a delay slot operation.

    :param address: Address to look above.
    :type address: ghidra.program.model.listing.Address

    :returns: Function name with () after it to resemble a function call or None
              if not found.
    :rtype: str
    """
    containing_function = getFunctionContaining(address)
    if not containing_function:
        return argument

    entry_point = containing_function.getEntryPoint()

    curr_addr = address
    curr_ins = getInstructionAt(curr_addr)

    # If the instruction is in the delay slot of a call skip above it.
    # This is not the call you are looking for.
    if curr_ins.isInDelaySlot() and utils.is_call_instruction(curr_ins.previous):
        curr_ins = curr_ins.previous.previous
        curr_addr = curr_ins.getAddress()

    while curr_addr and curr_addr > entry_point:
        if utils.is_call_instruction(curr_ins):
            ref = curr_ins.getReferencesFrom()
            if len(ref):
                function = getFunctionAt(ref[0].toAddress)
                if function:
                    return '%s()' % function.name

        curr_ins = curr_ins.previous

        if curr_ins:
            curr_addr = curr_ins.getAddress()
        else:
            break
    return None


def get_source(instruction):
    """
    Find source for the current instruction. Limited to strings and single
    registers currently.

    :param instruction: Instruction to find source data for.
    :type instruction: ghidra.program.model.listing.Instruction

    :returns: String representing the source entry or None
    :rtype: str
    """
    if not instruction:
        return None

    references = getReferencesFrom(instruction.getAddress())
    if references:
        for reference in references:
            data = getDataAt(reference.toAddress)
            if data:
                return '"%s"' % str(data.getValue()).encode('string_escape')

    input_objs = instruction.getInputObjects()
    if len(input_objs) == 1:
        input = input_objs[0].toString()
        if input in get_return_registers():
            return find_call(instruction.getAddress())
        return get_argument_source(instruction.getAddress(), input)
    else:
        return instruction.toString()

    return None


def get_argument_source(address, argument):
    """
    Find source of argument register.

    :param address: Address to start search.
    :type address: ghidra.program.model.listing.Address

    :param argument: Argument to search for.
    :type argument: str 

    :returns: Source for argument either as register string or full operation 
              string.
    :rtype: str
    """
    src = None
    containing_function = getFunctionContaining(address)
    if not containing_function:
        return argument

    entry_point = containing_function.getEntryPoint()

    curr_addr = address
    curr_ins = getInstructionAt(curr_addr)
    while curr_addr and curr_addr > entry_point:
        if curr_ins.getDelaySlotDepth() > 0:
            delay_slot = curr_ins.next
            destinations = get_destination(delay_slot)
            if destinations and argument in destinations:
                src = get_source(delay_slot)
                if src is None:
                    src = argument
                return src

        destinations = get_destination(curr_ins)
        if destinations and argument in destinations:
            src = get_source(curr_ins)
            break

        # This can cause false positives because of jumps and branches.
        # Should eventually convert this to use code blocks.
        curr_ins = curr_ins.previous

        if curr_ins:
            curr_addr = curr_ins.getAddress()
        else:
            break

    if src is None:
        src = argument

    return src


class FunctionPrototype(object):
    def __init__(self, function):
        self.function = function
        self.name = function.name
        self.entry_point = function.getEntryPoint()
        self.arg_count = 1
        self.has_var_args = function.hasVarArgs()

        if function.isExternal() or function.isThunk():
            self.arg_count = function.getAutoParameterCount()
        else:
            self.arg_count = self._get_argument_count()

    def _get_argument_count_manual(self):
        """
        Manual argument identification for function based on used argument
        registers in the function prior to setting them.

        :returns: Number of arguments used.
        :rtype: int
        """
        used_args = []
        arch_args = get_argument_registers()

        min_addr = self.function.body.minAddress
        max_addr = self.function.body.maxAddress

        curr_ins = getInstructionAt(min_addr)

        while curr_ins and curr_ins.getAddress() < max_addr:
            for op_index in range(0, curr_ins.getNumOperands()):
                ref_type = curr_ins.getOperandRefType(op_index)
                # We only care about looking at reads and writes. Reads that
                # include and index into a register show as 'data' so look
                # for those as well.
                if ref_type not in [RefType.WRITE, RefType.READ, RefType.DATA]:
                    continue

                # Check to see if the argument is an argument register. Remove
                # that register from the arch_args list so it can be ignored
                # from now on. If reading from the register add it to the
                # used_args list so we know its a used parameter.
                operands = curr_ins.getOpObjects(op_index)
                for operand in operands:
                    op_string = operand.toString()
                    if op_string in arch_args:
                        arch_args.remove(op_string)
                        if ref_type in [RefType.READ, RefType.DATA]:
                            used_args.append(op_string)
            curr_ins = curr_ins.next

        return len(used_args)

    def _get_argument_count(self):
        """
        Get argument count through decompiler if possible otherwise try to
        determine the argument count manually. Manual approach can miss
        arguments if they are used in the first function call of the function.
        """
        flat_api = FlatProgramAPI(currentProgram)
        decompiler_api = FlatDecompilerAPI(flat_api)

        # Must call decompile first or the decompiler will not be initialized.
        decompiler_api.decompile(self.function)
        decompiler = decompiler_api.getDecompiler()

        if decompiler:
            decompiled_fn = decompiler.decompileFunction(self.function,
                                                         10,
                                                         getMonitor())
            if decompiled_fn:
                high_level_fn = decompiled_fn.getHighFunction()
                if high_level_fn:
                    prototype = high_level_fn.getFunctionPrototype()
                    if prototype:
                        return prototype.getNumParams()

        return self._get_argument_count_manual()


class Call(object):
    def __init__(self, addr, containing_fn, function):
        self.address = addr
        self.containing_function = containing_fn
        self.function_call = function
        self.arguments = []

    def add_argument(self, argument):
        self.arguments.append(argument)

    def to_list(self):
        return [self.address.toString(), self.containing_function.name,
                self.function_call.name] + self.arguments


class Operator(object):
    def __init__(self):
        func_man = currentProgram.getFunctionManager()
        self._ref_man = currentProgram.getReferenceManager()

        self.function = None
        self.function_calls = []
        self._function_list = [func for func in func_man.getFunctions(True)]

    def get_callee(self):
        """
        Request user defined functions and identify when that function is 
        called.
        """
        self._function_list.sort(key=lambda func: func.name)

        function = askChoice('Select function',
                             'Select the starting function',
                             self._function_list,
                             self._function_list[0])

        self.function = FunctionPrototype(function)
        self._get_function_calls()

    def list_calls(self):
        """
        Display all times the identified function is called and the approximate
        registers / strings passed to the function.
        """
        if not len(self.function_calls):
            print 'No function calls to %s found.' % self.function.name
            return

        arg_registers = get_argument_registers()

        title = ['Address', 'Containing Function', 'Function']
        title.extend(arg_registers)

        calls = []
        for call in self.function_calls:
            containing_fn = getFunctionContaining(call)
            if not containing_fn:
                continue
            curr_call = Call(call, containing_fn, operator.function)
            arguments = arg_registers[:operator.function.arg_count]
            sources = []
            for arg in arguments:
                source = get_argument_source(call, arg)
                curr_call.add_argument(source)

            # Check for variable length arguments and format strings. Add
            # arguments if they are found.
            if operator.function.has_var_args:
                format_string_count = source.count('%') - source.count('\%')
                arg_count = operator.function.arg_count

                # Find additional arguments taking into account the number
                # of available argument registers.
                additional_arguments = arg_registers[
                    arg_count:
                    min(len(arg_registers),
                        format_string_count + operator.function.arg_count)]

                for arg in additional_arguments:
                    source = get_argument_source(call, arg)
                    curr_call.add_argument(source)

            curr_call_list = curr_call.to_list()
            calls.append(curr_call_list)

        calls.sort(key=lambda call: call[0])
        utils.table_pretty_print(title, calls)

    def _get_function_calls(self):
        """
        Find all calls to function specified by the user.
        """
        for ref in self._ref_man.getReferencesTo(self.function.entry_point):
            ref_type = ref.getReferenceType()
            if ref_type.isCall() or ref_type.isConditional():
                self.function_calls.append(ref.fromAddress)


utils.allowed_processors(currentProgram, ['MIPS', 'ARM'])

operator = Operator()
operator.get_callee()

print 'Identifying calls to %s...' % operator.function.name

operator.list_calls()
