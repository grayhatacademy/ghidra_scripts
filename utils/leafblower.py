from . import utils

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import BasicBlockModel


def get_argument_registers(current_program):
    """
    Get argument registers based on processor type.

    :param current_program: Ghidra program object.
    :type current_program: ghidra.program.model.listing.Program

    :returns: List of argument registers.
    :rtype: list(str)
    """
    arch = utils.get_processor(current_program)

    if arch == 'MIPS':
        return ['a0', 'a1', 'a2', 'a3']
    elif arch == 'ARM':
        return ['r0', 'r1', 'r2', 'r3']
    return []


class LeafFunction(object):
    """
    Class to hold leaf function candidates.
    """

    CANDIDATES_BY_ARGC = {
        1: ['atoi', 'atol', 'strlen'],
        2: ['strcpy', 'strcat', 'strcmp', 'strstr', 'strchr', 'strrchr',
            'bzero'],
        3: ['strtol', 'strncpy', 'strncat', 'strncmp', 'memcpy', 'memmove',
            'bcopy', 'memcmp', 'memset']
    }

    FORMAT_STR = '| {:<15} | {:^10} | {:^6} | {:<65} |'

    def __init__(self, function, has_loop, argument_count):
        self.name = function.getName()
        self.xref_count = function.getSymbol().getReferenceCount()
        self.has_loop = has_loop
        self.arg_count = argument_count
        self.candidates = LeafFunction.CANDIDATES_BY_ARGC[self.arg_count]

    def __str__(self):
        return LeafFunction.FORMAT_STR.format(self.name,
                                              self.xref_count,
                                              self.arg_count,
                                              ','.join(self.candidates))

    @classmethod
    def is_candidate(cls, function, has_loop, argument_count):
        """
        Determine is a function is a candidate for a leaf function. Leaf 
        functions must have loops, make no external calls, require 1-3 
        arguments, and have a reference count greater than 25. 
        """
        if not has_loop:
            return False

        if argument_count > 3 or argument_count == 0:
            return False

        if function.getSymbol().getReferenceCount() < 25:
            return False

        return True


class LeafFunctionFinder(object):
    """
    Leaf function finder class. 
    """

    def __init__(self, program):
        self.leaf_functions = []
        self._program = program
        self._flat_api = FlatProgramAPI(program)

    def find_leaves(self):
        """
        Find leaf functions. Leaf functions are functions that have loops,
        make no external calls, require 1-3 arguments, and have a reference 
        count greater than 25.
        """
        function_manager = self._program.getFunctionManager()

        for function in function_manager.getFunctions(True):
            if not self._function_makes_call(function):
                loops = self._function_has_loops(function)
                argc = self._get_argument_count(function)

                if LeafFunction.is_candidate(function, loops, argc):
                    self.leaf_functions.append(LeafFunction(function,
                                                            loops,
                                                            argc))

        self.leaf_functions.sort(key=lambda x: x.xref_count, reverse=True)

    def display(self):
        """
        Print leaf function candidates to the terminal.
        """
        lines = [str(leaf) for leaf in self.leaf_functions]
        max_line_len = len(max(lines))

        print '=' * max_line_len
        print LeafFunction.FORMAT_STR.format('Function', 'XRefs', 'Args',
                                             'Potential Function')
        print '=' * max_line_len
        for line in lines:
            print line

        print '-' * max_line_len

    def _function_makes_call(self, function):
        """
        Determine if a function makes external calls.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: True if the function makes external calls, False otherwise.
        :rtype: bool
        """
        function_body = function.getBody()
        min_addr = function_body.minAddress
        max_addr = function_body.maxAddress

        curr_addr = min_addr
        while curr_addr <= max_addr:
            instruction = self._flat_api.getInstructionAt(curr_addr)
            if utils.is_call_instruction(instruction):
                return True
            curr_addr = curr_addr.next()
        return False

    def _function_has_loops(self, function):
        """
        Determine if a function has internal loops.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: True if the function has loops, False otherwise.
        :rtype: bool
        """
        monitor = self._flat_api.getMonitor()
        basic_blocks = BasicBlockModel(self._program)

        function_blocks = basic_blocks.getCodeBlocksContaining(function.body,
                                                               monitor)

        while function_blocks.hasNext():
            block = function_blocks.next()
            destinations = block.getDestinations(monitor)

            # Determine if the current block can result in jumping to a block
            # above the end address and in the same function. This indicates
            # an internal loop.
            while destinations.hasNext():
                destination = destinations.next()
                dest_addr = destination.getDestinationAddress()
                destination_function = self._flat_api.getFunctionContaining(
                    dest_addr)
                if destination_function == function and \
                        dest_addr <= block.minAddress:
                    return True
        return False

    def _get_argument_count(self, function):
        """
        Determine the argument count to the function. This is determined by 
        inspecting argument registers to see if they are read from prior to 
        being written to.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: Argument count.
        :rtype: int
        """
        used_args = []
        arch_args = get_argument_registers(self._program)

        min_addr = function.body.minAddress
        max_addr = function.body.maxAddress

        curr_ins = self._flat_api.getInstructionAt(min_addr)

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
