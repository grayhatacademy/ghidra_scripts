# Fixup .data and .rodata sections by defining strings and forcing remaining undefined data to be a DWORD.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Codatify.Fixup Data


from utils import functiontable

from ghidra.program.model.data import PointerDataType


def find_data_sections():
    """
    Search for non-executable sections in the memory map.
    """
    data_sections = []

    # Find all memory sections and remove the executable sections.
    addr_factory = currentProgram.getAddressFactory()
    memory_manager = currentProgram.getMemory()
    address_ranges = memory_manager.getLoadedAndInitializedAddressSet()
    executable_set = memory_manager.getExecuteSet()

    addr_view = address_ranges.xor(executable_set)

    for section in addr_view:
        new_view = addr_factory.getAddressSet(section.getMinAddress(),
                                              section.getMaxAddress())
        data_sections.append(new_view)

    return data_sections


def define_strings(section):
    """
    Convert undefined strings in the section provided to ascii.

    :param section: Section to search for undefined strings.
    :type section: ghidra.program.model.listing.ProgramFragment
    """
    if section is None:
        return

    strings = findStrings(section, 1, 1, True, True)

    string_count = 0
    for string in strings:
        if getUndefinedDataAt(string.getAddress()):
            try:
                createAsciiString(string.getAddress())
                string_count += 1
            except:
                continue

    print 'Strings - {}'.format(string_count)


def get_pointer_type():
    """
    Get the correct pointer size for the current architecture.
    """
    return PointerDataType(None, currentProgram.getDefaultPointerSize())


def define_pointers(section):
    """
    Convert undefined data to valid pointers. 

    :param section: The section to convert pointers in.
    :type section: ghidra.program.model.listing.ProgramFragment
    """
    if section is None:
        return

    start_addr = section.getMinAddress()
    end_addr = section.getMaxAddress()

    undefined_data = getUndefinedDataAt(start_addr)
    if undefined_data is None:
        undefined_data = getUndefinedDataAfter(start_addr)

    pointer_count = 0
    pointer_type = get_pointer_type()
    memory_manager = currentProgram.getMemory()

    while undefined_data is not None and undefined_data.getAddress() < end_addr:
        undefined_addr = undefined_data.getAddress()
        try:
            # At each undefined byte, convert it to a pointer and see if it
            # has any valid references. If it does validate the reference goes
            # to a valid memory address using the memory manager.
            createData(undefined_addr, pointer_type)
            references = getReferencesFrom(undefined_addr)
            if len(references):
                if memory_manager.contains(references[0].getToAddress()):
                    pointer_count += 1
                else:
                    removeDataAt(undefined_addr)
            else:
                removeDataAt(undefined_addr)
        except:
            pass
        finally:
            undefined_data = getUndefinedDataAfter(undefined_addr)

    print 'Pointers - {}'.format(pointer_count)


def define_data(section):
    """
    Convert undefined data to a DWORD.

    :param section: Section to search for undefined data in.
    :type section: hidra.program.model.listing.ProgramFragment
    """
    if section is None:
        return

    start_addr = section.getMinAddress()
    end_addr = section.getMaxAddress()

    undefined_data = getUndefinedDataAt(start_addr)
    if undefined_data is None:
        undefined_data = getUndefinedDataAfter(start_addr)

    data_count = 0
    while undefined_data is not None and undefined_data.getAddress() < end_addr:
        undefined_addr = undefined_data.getAddress()
        undefined_data = getUndefinedDataAfter(undefined_addr)
        try:
            createDWord(undefined_addr)
            data_count += 1
        except:
            continue

    print 'DWORDS - {}'.format(data_count)


def fixup_section(section):
    """
    Fixup the section by defining strings and converting undefined data to 
    DWORDs.

    :param section: Section to fixup.
    :type section: str
    """
    print 'Section {} - {}'.format(section.getMinAddress(),
                                   section.getMaxAddress())
    print '-' * 30

    define_pointers(section)
    define_strings(section)
    define_data(section)

    ft_finder = functiontable.Finder(currentProgram, section)
    ft_finder.find_function_table()
    ft_finder.rename_functions()

    print '\n'


# Base address of 0 can really mess things up when fixing up pointers.
# Make sure the user really wants this.
base_addr = currentProgram.getMinAddress()
if base_addr.toString() == u'00000000' and \
    not askYesNo('Base Address Zero', 'The base address is set to 0 which can '
                 'introduce a large amount of false positives when fixing up '
                 'the data section. \nDo you want to continue?'):
    exit(0)

data_sections = find_data_sections()

print 'Fixing up data...\n'
for section in data_sections:
    fixup_section(section)
