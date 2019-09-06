# Fixup .data and .rodata sections by defining strings and forcing remaining undefined data to be a DWORD.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Codatify.Fixup Data


def get_section(section):
    """
    Find section in the code by name.

    :param section: Section to find.
    :type section: str

    :returns: Section if found, None otherwise.
    :rtype: ghidra.program.model.listing.ProgramFragment
    """
    listing = currentProgram.getListing()
    return getFragment(listing.getRootModule(0), section)


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

    print 'Defined {} new ascii strings in {}.'.format(string_count,
                                                       section.getName())


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

    print 'Converted {} undefined data entries to DWORDs in {}'.format(
        data_count, section.getName())


def fixup_section(section):
    """
    Fixup the section by defining strings and converting undefined data to 
    DWORDs.

    :param section: Section to fixup.
    :type section: str
    """
    curr_section = get_section(section)
    define_strings(curr_section)
    define_data(curr_section)


fixup_section('.rodata')
fixup_section('.data')
