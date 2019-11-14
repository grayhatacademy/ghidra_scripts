# Fixup .data and .rodata sections by defining strings and forcing remaining undefined data to be a DWORD.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Codatify.Fixup Data


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

    print 'Defined {} new ascii strings in range {} -> {}.'.format(
        string_count, section.getMinAddress(), section.getMaxAddress())


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

    print 'Converted {} undefined data entries to DWORDs in range {} -> {}'.format(
        data_count, section.getMinAddress(), section.getMaxAddress())


def fixup_section(section):
    """
    Fixup the section by defining strings and converting undefined data to 
    DWORDs.

    :param section: Section to fixup.
    :type section: str
    """
    define_strings(section)
    define_data(section)


data_sections = find_data_sections()

for section in data_sections:
    fixup_section(section)
