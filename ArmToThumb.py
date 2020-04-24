# Convert executable sections to Thumb instructions to find new gadgets.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.Convert To Thumb

from utils import utils

from ghidra.util.task import CancelledListener
from ghidra.app.services import ConsoleService
from ghidra.app.cmd.disassemble import ArmDisassembleCommand


utils.allowed_processors(currentProgram, 'ARM')


def find_code():
    """
    Find executable code sections and return an address set representing the 
    range.
    """
    code_sections = []

    addr_factory = currentProgram.getAddressFactory()
    memory_manager = currentProgram.getMemory()
    addr_view = memory_manager.getExecuteSet()

    for section in addr_view:
        new_view = addr_factory.getAddressSet(section.getMinAddress(),
                                              section.getMaxAddress())
        code_sections.append(new_view)

    return code_sections


class CancelListener(CancelledListener):
    def __init__(self, transaction):
        super(CancelledListener, self).__init__()
        self.transaction = transaction

    def cancelled(self):
        if self.transaction:
            print('User cancelled, cleaning up Thumb disassembly.')
            currentProgram.endTransaction(self.transaction, False)
            self.transaction = None


code_manager = currentProgram.getCodeManager()
addr_factory = currentProgram.getAddressFactory()
code_sections = find_code()

try:
    transaction = currentProgram.startTransaction('thumb')
    commit_changes = True

    # Create a cancel listener so we can cleanup if the user cancels the
    # operation
    cancel = CancelListener(transaction)
    monitor = getMonitor()
    monitor.addCancelledListener(cancel)

    for section in code_sections:
        print 'Converting operations to Thumb in section %s' % section
        clearListing(section)
        undefined = code_manager.getFirstUndefinedData(section, monitor)
        while undefined and undefined.getAddress() < section.getMaxAddress():
            curr_address = undefined.getAddress()

            # Create an address set on a single instruction. If more than one
            # instruction is performed at a time it will follow jumps and
            # disassemble code elsewhere, likely as ARM instructions.
            single_ins = addr_factory.getAddressSet(curr_address, curr_address)
            disassm = ArmDisassembleCommand(single_ins, single_ins, True)
            disassm.enableCodeAnalysis(False)
            disassm.applyTo(currentProgram)
            undefined = code_manager.getFirstUndefinedDataAfter(
                curr_address, monitor)
except Exception as e:
    print str(e)
    commit_changes = False
finally:
    currentProgram.endTransaction(transaction, commit_changes)
    monitor.removeCancelledListener(cancel)
