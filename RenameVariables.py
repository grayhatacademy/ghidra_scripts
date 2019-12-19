# Rename saved stack variables in MIPS programs.
#@author fuzzywalls
#@category TNS
#@keybinding
#@menupath TNS.Rename Variables

from utils import utils
from ghidra.program.model.symbol import SourceType


utils.allowed_processors(currentProgram, 'MIPS')

func_man = currentProgram.getFunctionManager()
code_man = currentProgram.getCodeManager()

func_list = func_man.getFunctions(True)


for func in func_list:
    # Order of this list is important.
    savable_registers = ['gp', 's0', 's1', 's2',
                         's3', 's4', 's5', 's6', 's7', 's8', 'ra']

    variables = func.getAllVariables()
    for var in variables:
        if len(savable_registers) == 0:
            break

        symbol = var.getSymbol()
        if not symbol:
            continue

        references = symbol.getReferences()

        for ref in references:
            ins = code_man.getInstructionAt(ref.getFromAddress())

            if 'sw ' in str(ins) or 'sd ' in str(ins):
                saved_register = ins.getRegister(0)
                if saved_register:
                    saved_register = saved_register.toString()
                    if saved_register in savable_registers:
                        var.setName('saved_%s' % saved_register,
                                    SourceType.USER_DEFINED)

                        # Remove the saved register to avoid renaming registers
                        # saved later.
                        savable_registers.remove(saved_register)
