# Find MIPS ROP gadgets for gaining control of more registers through function epilogues.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Epilogue


from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

min_reg = askChoice('Minimum Register', 
                    'What is the lowest register you want to control?', 
                    ['Any', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8'],
                    'Any')
if min_reg == 'Any':
    min_reg = None
    
if min_reg:
    print 'Searching for function epilogues that grant control of registers up to %s...' % min_reg

epilogue = mipsrop.MipsInstruction('.*lw', 'ra')

mips_rop = mipsrop.MipsRop(currentProgram)
function_epilogue = mips_rop.find_instructions([epilogue], 
                                               overwrite_register=min_reg)

function_epilogue.pretty_print()