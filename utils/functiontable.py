import string

from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI


def is_valid_function_name(function_name):
    """
    Determine if a function name is valid.

    :param function_name: Function name to inspect.
    :type function_name: unicode

    :returns: True if valid function name, false otherwise.
    :rtype: bool
    """
    if not isinstance(function_name, unicode):
        return False

    if function_name[0] not in string.ascii_letters + '_':
        return False
    for letter in function_name[1:]:
        if letter not in string.ascii_letters + '_' + string.digits:
            return False
    return True


class Element(object):
    """
    Single element in a structure.
    """

    def __init__(self, program, address):
        self._program = program
        self._flat_api = FlatProgramAPI(self._program)
        self._data = self._flat_api.getDataAt(address)

        self.address = address
        self.type = None
        self.value = None

        if not self._data:
            return

        # Determine the data's type and set the type/value accordingly.
        if self._data.isPointer():
            reference = self._data.getPrimaryReference(0)
            if not reference:
                return

            to_addr = reference.toAddress
            func = self._flat_api.getFunctionAt(to_addr)
            if func:
                self.type = 'function'
                self.value = func
            else:
                value = self._flat_api.getDataAt(to_addr)
                if value:
                    self.type = 'data'
                    self.value = value
        else:
            self.type = self._data.dataType
            self.value = self._data


class Structure(object):
    """
    Declared structure
    """

    def __init__(self, program, address, element_count, length=0):
        self._program = program
        self._element_size = self._program.getDefaultPointerSize()

        self.address = address
        self.elements = []
        self.length = length

        curr_addr = self.address
        for i in range(0, element_count):
            element = Element(self._program, curr_addr)
            self.elements.append(element)
            curr_addr = curr_addr.add(self._element_size)
            if not curr_addr:
                break

    def get_pattern(self):
        """
        Get the element pattern for this structure.

        :returns: List of element types.
        :rtype: list(objects)
        """
        return [element.type for element in self.elements]

    def get_function(self):
        """
        Each valid structure *should* contains one function. Find and return it.

        :returns: Function, if found, None otherwise.
        :rtype: ghidra.program.model.listing.Function or None
        """
        for element in self.elements:
            if element.type == 'function':
                return element.value
        return None

    def get_string(self):
        """
        Each valid structure *should* contains one string. Find and return it.

        :returns: String, if found, None otherwise.
        :rtype: str or None
        """
        for element in self.elements:
            if element.type == 'data':
                return element.value.getValue()
        return None

    def next(self):
        """
        Get the next structure in the structure array.

        :returns: Next structure or None if at the end of the array.
        :rtype: Structure or None
        """
        if self.length <= 0:
            return None

        next_addr = self.address.add(len(self.elements) * self._element_size)

        return Structure(self._program, next_addr, len(self.elements),
                         self.length - 1)


class StructureFinder(object):
    """
    Search for structures that appear to represent a function table at the 
    specified address.
    """

    def __init__(self, program, address):
        self._program = program
        self.address = address
        self.pattern_length = 0
        self.length = 1
        self._element_size = self._program.getDefaultPointerSize()
        self.structure = Structure(program, address, 16)

    def has_pattern(self):
        """
        Determine if there is a structure pattern within 16 elements of the
        provided start address.

        :returns: True if a pattern was found, False otherwise.
        :rtype: bool
        """
        for i in range(2, len(self.structure.elements) / 2):
            blk_one = self.structure.elements[:i]
            pattern_one = [element.type for element in blk_one]

            blk_two = self.structure.elements[i:i + i]
            pattern_two = [element.type for element in blk_two]

            # Valid patterns can only have one function and one data element.
            if 'function' not in pattern_one or 'data' not in pattern_one:
                continue

            if 1 != pattern_one.count('function'):
                continue
            if 1 != pattern_one.count('data'):
                continue

            if pattern_one == pattern_two:
                self.pattern_length = len(pattern_one)
                return True
        return False

    def _get_next_struct(self, address):
        """
        Get the next apparent structure in the structure array.

        :returns: Next structure in the array.
        :rtype: Structure
        """
        next_addr = address.add(
            self.pattern_length * self._element_size)
        return Structure(self._program, next_addr, self.pattern_length)

    def find_length(self):
        """
        Determine the length of the structure array by casting the next entry
        until the pattern no longer matches.

        :returns: Length of structure array.
        :rtype: int
        """
        if self.pattern_length == 0:
            return 0

        first_entry = Structure(
            self._program, self.address, self.pattern_length)
        pattern = first_entry.get_pattern()

        next_entry = self._get_next_struct(self.address)

        while next_entry and next_entry.get_pattern() == pattern:
            self.length += 1
            next_entry = self._get_next_struct(next_entry.address)

        return self.length

    def get_next_search(self):
        """
        Get the next structure search.

        :returns: Structure finder object after this one.
        :rtype: StructureFinder
        """
        curr_addr = self.address
        next_addr = self.length * self._element_size

        if self.pattern_length:
            next_addr *= self.pattern_length
        next_struct = curr_addr.add(next_addr)
        return StructureFinder(self._program, next_struct)


class Finder(object):
    """
    Find function tables in the current program and rename them.
    """

    def __init__(self, program, section):
        self._program = program
        self._min_address = section.getMinAddress()
        self._max_address = section.getMaxAddress()
        self._element_size = self._program.getDefaultPointerSize()

        self.structs = []

    def find_function_table(self):
        """
        Find suspected function tables within the current section.
        """
        struct = StructureFinder(self._program, self._min_address)
        while struct and struct.address < self._max_address:
            if struct.has_pattern():
                length = struct.find_length()
                new_struct = Structure(self._program,
                                       struct.address,
                                       struct.pattern_length,
                                       length)

                self.structs.append(new_struct)
            struct = struct.get_next_search()

    def rename_functions(self):
        """
        Rename unnamed functions from suspected function tables.
        """
        renames = 0
        for struct in self.structs:
            curr_struct = struct
            while curr_struct:
                function = curr_struct.get_function()
                if function:
                    curr_name = function.getName()
                    if curr_name.startswith('FUN_'):
                        new_name = curr_struct.get_string()
                        if new_name and is_valid_function_name(new_name):
                            function.setName(new_name, SourceType.USER_DEFINED)
                            renames += 1

                curr_struct = curr_struct.next()

        print 'Function Names - %d' % renames
