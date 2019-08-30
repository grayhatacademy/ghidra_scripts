# Find all cross references in the current function.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Function Profiler

from utils import utils
from ghidra.program.model.symbol import RefType,SymbolType


class CrossRef(object):
    def __init__(self, reference):
        to_addr = reference.getToAddress()
        symbol = getSymbolAt(to_addr)

        self.from_addr = reference.getFromAddress()
        self.symbol_type = str(symbol.getSymbolType())

        symbol_object = symbol.getObject()
        try:
            if symbol_object.hasStringValue():
                symbol_name = str(symbol.getObject())
                if symbol_name.startswith('ds '):
                    self.symbol_name = symbol_name[3:]
                self.symbol_type = 'String'
            else:
                self.symbol_name = symbol.getName() 
        except AttributeError:
            self.symbol_name = symbol.getName() 
            
    def __str__(self):
        return '{:12} {}'.format(self.from_addr, self.symbol_name)


class FunctionCrossReferences(object):
    def __init__(self, function):
        self.function = function
        self.cross_references = []
        
    def append(self, cross_ref):
        self.cross_references.append(cross_ref)
        
    def _loop_print(self, label):
        print '\n{}\n{}'.format(label, '-' * len(label))
        for cr in self.cross_references:
            if cr.symbol_type == label:
                print cr
        
    def pretty_print(self):
        print '\nCross References in {}\n{}'.format(function, '-' * 30)
        self._loop_print('String')
        self._loop_print('Function')
        self._loop_print('Label')
        print

code_manager = currentProgram.getCodeManager()
function_manager = currentProgram.getFunctionManager()
function = utils.get_function(function_manager, currentLocation.address)

if function is None:
    print 'Current selection is not a function.'
    exit()


cross_references = FunctionCrossReferences(function)

instructions = utils.get_instruction_list(code_manager, function)
for instruction in instructions:
    for reference in instruction.getReferencesFrom():
        ref_type = reference.getReferenceType()
        if reference.isMemoryReference() and \
        ref_type != RefType.CONDITIONAL_JUMP and \
        ref_type != RefType.UNCONDITIONAL_JUMP:
            cross_references.append(CrossRef(reference))
            
cross_references.pretty_print()
