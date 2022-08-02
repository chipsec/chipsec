import random
import struct


########################################################################################################################


class base_primitive:
    '''
    The primitive base class implements common functionality shared across most primitives.
    '''

    def __init__(self):
        self.fuzz_complete = False     # this flag is raised when the mutations are exhausted.
        self.fuzz_library = []        # library of static fuzz heuristics to cycle through.
        self.fuzzable = True      # flag controlling whether or not the given primitive is to be fuzzed.
        self.mutant_index = 0         # current mutation index into the fuzz library.
        self.original_value = None      # original value of primitive.
        self.rendered = ""        # rendered value of primitive.
        self.value = None      # current value of primitive.

    def exhaust(self):
        '''
        Exhaust the possible mutations for this primitive.

        @rtype:  Integer
        @return: The number of mutations to reach exhaustion
        '''

        num = self.num_mutations() - self.mutant_index

        self.fuzz_complete = True
        self.mutant_index = self.num_mutations()
        self.value = self.original_value

        return num

    def mutate(self):
        '''
        Mutate the primitive by stepping through the fuzz library, return False on completion.

        @rtype:  Boolean
        @return: True on success, False otherwise.
        '''

        # if we've ran out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.original_value
            return False

        # update the current value from the fuzz library.
        self.value = self.fuzz_library[self.mutant_index]

        # increment the mutation count.
        self.mutant_index += 1

        return True

    def num_mutations(self):
        '''
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  Integer
        @return: Number of mutated forms this primitive can take
        '''

        return len(self.fuzz_library)

    def render(self):
        '''
        Nothing fancy on render, simply return the value.
        '''

        self.rendered = self.value
        return self.rendered

    def reset(self):
        '''
        Reset this primitive to the starting mutation state.
        '''

        self.fuzz_complete = False
        self.mutant_index = 0
        self.value = self.original_value


########################################################################################################################
class delim(base_primitive):
    def __init__(self, value, fuzzable=True, name=None):
        '''
        Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition, substitution and exclusion.

        @type  value:    Character
        @param value:    Original value
        @type  fuzzable: Boolean
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:     String
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''
        super(delim, self).__init__()
        self.value = self.original_value = value
        self.fuzzable = fuzzable
        self.name = name

        self.s_type = "delim"   # for ease of object identification

        #
        # build the library of fuzz heuristics.
        #

        # if the default delim is not blank, repeat it a bunch of times.
        if self.value:
            self.fuzz_library.append(self.value * 2)
            self.fuzz_library.append(self.value * 5)
            self.fuzz_library.append(self.value * 10)
            self.fuzz_library.append(self.value * 25)
            self.fuzz_library.append(self.value * 100)
            self.fuzz_library.append(self.value * 500)
            self.fuzz_library.append(self.value * 1000)

        # try omitting the delimiter.
        self.fuzz_library.append("")

        # if the delimiter is a space, try throwing out some tabs.
        if self.value == " ":
            self.fuzz_library.append("\t")
            self.fuzz_library.append("\t" * 2)
            self.fuzz_library.append("\t" * 100)

        # toss in some other common delimiters:
        self.fuzz_library.append(" ")
        self.fuzz_library.append("\t")
        self.fuzz_library.append("\t " * 100)
        self.fuzz_library.append("\t\r\n" * 100)
        self.fuzz_library.append("!")
        self.fuzz_library.append("@")
        self.fuzz_library.append("#")
        self.fuzz_library.append("$")
        self.fuzz_library.append("%")
        self.fuzz_library.append("^")
        self.fuzz_library.append("&")
        self.fuzz_library.append("*")
        self.fuzz_library.append("(")
        self.fuzz_library.append(")")
        self.fuzz_library.append("-")
        self.fuzz_library.append("_")
        self.fuzz_library.append("+")
        self.fuzz_library.append("=")
        self.fuzz_library.append(":")
        self.fuzz_library.append(": " * 100)
        self.fuzz_library.append(":7" * 100)
        self.fuzz_library.append(";")
        self.fuzz_library.append("'")
        self.fuzz_library.append("\"")
        self.fuzz_library.append("/")
        self.fuzz_library.append("\\")
        self.fuzz_library.append("?")
        self.fuzz_library.append("<")
        self.fuzz_library.append(">")
        self.fuzz_library.append(".")
        self.fuzz_library.append(",")
        self.fuzz_library.append("\r")
        self.fuzz_library.append("\n")
        self.fuzz_library.append("\r\n" * 64)
        self.fuzz_library.append("\r\n" * 128)
        self.fuzz_library.append("\r\n" * 512)


########################################################################################################################
class group(base_primitive):
    def __init__(self, name, values):
        '''
        This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
        to a group primitive to specify that the block should cycle through all possible mutations for *each* value
        within the group. The group primitive is useful for example for representing a list of valid opcodes.

        @type  name:   String
        @param name:   Name of group
        @type  values: List or raw data
        @param values: List of possible raw values this group can take.
        '''
        super(group, self).__init__()
        self.name = name
        self.values = values
        self.fuzzable = True

        self.s_type = "group"
        self.value = self.values[0]
        self.original_value = self.values[0]

        # sanity check that values list only contains strings (or raw data)
        if self.values != []:
            for val in self.values:
                assert isinstance(val, str), "Value list may only contain strings or raw data"

    def mutate(self):
        '''
        Move to the next item in the values list.

        @rtype:  False
        @return: False
        '''

        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.values[0]
            return False

        # step through the value list.
        self.value = self.values[self.mutant_index]

        # increment the mutation count.
        self.mutant_index += 1

        return True

    def num_mutations(self):
        '''
        Number of values in this primitive.

        @rtype:  Integer
        @return: Number of values in this primitive.
        '''

        return len(self.values)


########################################################################################################################
class random_data(base_primitive):
    def __init__(self, value, min_length, max_length, max_mutations=25, fuzzable=True, step=None, name=None):
        '''
        Generate a random chunk of data while maintaining a copy of the original. A random length range can be specified.
        For a static length, set min/max length to be the same.

        @type  value:         Raw
        @param value:         Original value
        @type  min_length:    Integer
        @param min_length:    Minimum length of random block
        @type  max_length:    Integer
        @param max_length:    Maximum length of random block
        @type  max_mutations: Integer
        @param max_mutations: (Optional, def=25) Number of mutations to make before reverting to default
        @type  fuzzable:      Boolean
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  step:          Integer
        @param step:          (Optional, def=None) If not null, step count between min and max reps, otherwise random
        @type  name:          String
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        super(random_data, self).__init__()
        self.value = self.original_value = str(value)
        self.min_length = min_length
        self.max_length = max_length
        self.max_mutations = max_mutations
        self.fuzzable = fuzzable
        self.step = step
        self.name = name

        self.s_type = "random_data"  # for ease of object identification

        if self.step:
            self.max_mutations = (self.max_length - self.min_length) // self.step + 1

    def mutate(self):
        '''
        Mutate the primitive value returning False on completion.

        @rtype:  Boolean
        @return: True on success, False otherwise.
        '''

        # if we've ran out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.original_value
            return False

        # select a random length for this string.
        if not self.step:
            length = random.randint(self.min_length, self.max_length)
        # select a length function of the mutant index and the step.
        else:
            length = self.min_length + self.mutant_index * self.step

        # reset the value and generate a random string of the determined length.
        self.value = b""
        for i in range(length):
            self.value += struct.pack("B", random.randint(0, 255))

        # increment the mutation count.
        self.mutant_index += 1

        return True

    def num_mutations(self):
        '''
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  Integer
        @return: Number of mutated forms this primitive can take
        '''

        return self.max_mutations


########################################################################################################################
class static(base_primitive):
    def __init__(self, value, name=None):
        '''
        Primitive that contains static content.

        @type  value: Raw
        @param value: Raw static data
        @type  name:  String
        @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        super(static, self).__init__()
        self.value = self.original_value = value
        self.name = name
        self.fuzzable = False       # every primitive needs this attribute.
        self.s_type = "static"    # for ease of object identification
        self.fuzz_complete = True

    def mutate(self):
        '''
        Do nothing.

        @rtype:  False
        @return: False
        '''

        return False

    def num_mutations(self):
        '''
        Return 0.

        @rtype:  0
        @return: 0
        '''

        return 0


########################################################################################################################
class string(base_primitive):
    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    fuzz_library = []

    def __init__(self, value, size=-1, padding="\x00", encoding="ascii", fuzzable=True, max_len=0, name=None):
        '''
        Primitive that cycles through a library of "bad" strings. The class variable 'fuzz_library' contains a list of
        smart fuzz values global across all instances. The 'this_library' variable contains fuzz values specific to
        the instantiated primitive. This allows us to avoid copying the near ~70MB fuzz_library data structure across
        each instantiated primitive.

        @type  value:    String
        @param value:    Default string value
        @type  size:     Integer
        @param size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
        @type  padding:  Character
        @param padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
        @type  encoding: String
        @param encoding: (Optonal, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
        @type  fuzzable: Boolean
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  max_len:  Integer
        @param max_len:  (Optional, def=0) Maximum string length
        @type  name:     String
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        super(string, self).__init__()
        self.value = self.original_value = value
        self.size = size
        self.padding = padding
        self.encoding = encoding
        self.fuzzable = fuzzable
        self.name = name

        self.s_type = "string"  # for ease of object identification

        # add this specific primitives repitition values to the unique fuzz library.
        self.this_library = \
            [
                self.value * 2,
                self.value * 10,
                self.value * 100,

                # UTF-8
                self.value * 2 + "\xfe",
                self.value * 10 + "\xfe",
                self.value * 100 + "\xfe",
            ]

        # if the fuzz library has not yet been initialized, do so with all the global values.
        if not self.fuzz_library:
            string.fuzz_library = \
                [
                    # omission.
                    "",

                    # strings ripped from spike (and some others I added)
                    "/.:/" + "A" * 5000 + "\x00\x00",
                    "/.../" + "A" * 5000 + "\x00\x00",
                    "/.../.../.../.../.../.../.../.../.../.../",
                    "/../../../../../../../../../../../../etc/passwd",
                    "/../../../../../../../../../../../../boot.ini",
                    "..:..:..:..:..:..:..:..:..:..:..:..:..:",
                    "\\\\*",
                    "\\\\?\\",
                    "/\\" * 5000,
                    "/." * 5000,
                    "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
                    "%01%02%03%04%0a%0d%0aADSF",
                    "%01%02%03@%04%0a%0d%0aADSF",
                    "/%00/",
                    "%00/",
                    "%00",
                    "%u0000",
                    "%\xfe\xf0%\x00\xff",
                    "%\xfe\xf0%\x01\xff" * 20,

                    # format strings.
                    "%n" * 100,
                    "%n" * 500,
                    "\"%n\"" * 500,
                    "%s" * 100,
                    "%s" * 500,
                    "\"%s\"" * 500,

                    # command injection.
                    "|touch /tmp/SULLEY",
                    ";touch /tmp/SULLEY;",
                    "|notepad",
                    ";notepad;",
                    "\nnotepad\n",

                    # SQL injection.
                    "1;SELECT%20*",
                    "'sqlattempt1",
                    "(sqlattempt2)",
                    "OR%201=1",

                    # some binary strings.
                    "\xde\xad\xbe\xef",
                    "\xde\xad\xbe\xef" * 10,
                    "\xde\xad\xbe\xef" * 100,
                    "\xde\xad\xbe\xef" * 1000,
                    "\xde\xad\xbe\xef" * 10000,
                    "\x00" * 1000,

                    # miscellaneous.
                    "\r\n" * 100,
                    "<>" * 500,         # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
                ]

            # add some long strings.
            self.add_long_strings("A")
            self.add_long_strings("B")
            self.add_long_strings("1")
            self.add_long_strings("2")
            self.add_long_strings("3")
            self.add_long_strings("<")
            self.add_long_strings(">")
            self.add_long_strings("'")
            self.add_long_strings("\"")
            self.add_long_strings("/")
            self.add_long_strings("\\")
            self.add_long_strings("?")
            self.add_long_strings("=")
            self.add_long_strings("a=")
            self.add_long_strings("&")
            self.add_long_strings(".")
            self.add_long_strings(",")
            self.add_long_strings("(")
            self.add_long_strings(")")
            self.add_long_strings("]")
            self.add_long_strings("[")
            self.add_long_strings("%")
            self.add_long_strings("*")
            self.add_long_strings("-")
            self.add_long_strings("+")
            self.add_long_strings("{")
            self.add_long_strings("}")
            self.add_long_strings("\x14")
            self.add_long_strings("\xFE")   # expands to 4 characters under utf16
            self.add_long_strings("\xFF")   # expands to 4 characters under utf16

            # add some long strings with null bytes thrown in the middle of it.
            for length in [128, 256, 1024, 2048, 4096, 32767, 0xFFFF]:
                s = "B" * length
                s = s[:len(s) // 2] + "\x00" + s[len(s) // 2:]
                string.fuzz_library.append(s)

            # if the optional file '.fuzz_strings' is found, parse each line as a new entry for the fuzz library.
            try:
                fh = open(".fuzz_strings", "r")

                for fuzz_string in fh.readlines():
                    fuzz_string = fuzz_string.rstrip("\r\n")

                    if fuzz_string != "":
                        string.fuzz_library.append(fuzz_string)

                fh.close()
            except:
                pass

        # delete strings which length is greater than max_len.
        if max_len > 0:
            if any(len(s) > max_len for s in self.this_library):
                self.this_library = list(set([s[:max_len] for s in self.this_library]))

            if any(len(s) > max_len for s in self.fuzz_library):
                self.fuzz_library = list(set([s[:max_len] for s in self.fuzz_library]))

    def add_long_strings(self, sequence):
        '''
        Given a sequence, generate a number of selectively chosen strings lengths of the given sequence and add to the
        string heuristic library.

        @type  sequence: String
        @param sequence: Sequence to repeat for creation of fuzz strings.
        '''

        for length in [128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF - 2, 0xFFFF - 1, 0xFFFF, 0xFFFF + 1,
                       0xFFFF + 2, 99999, 100000, 500000, 1000000]:

            long_string = sequence * length
            string.fuzz_library.append(long_string)

    def mutate(self):
        '''
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        @rtype:  Boolean
        @return: True on success, False otherwise.
        '''

        # loop through the fuzz library until a suitable match is found.
        while 1:
            # if we've ran out of mutations, raise the completion flag.
            if self.mutant_index == self.num_mutations():
                self.fuzz_complete = True

            # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
            if not self.fuzzable or self.fuzz_complete:
                self.value = self.original_value
                return False

            # update the current value from the fuzz library.
            self.value = (self.fuzz_library + self.this_library)[self.mutant_index]

            # increment the mutation count.
            self.mutant_index += 1

            # if the size parameter is disabled, break out of the loop right now.
            if self.size == -1:
                break

            # ignore library items greater then user-supplied length.
            # TODO: might want to make this smarter.
            if len(self.value) > self.size:
                continue

            # pad undersized library items.
            if len(self.value) < self.size:
                self.value = self.value + self.padding * (self.size - len(self.value))
                break

        return True

    def num_mutations(self):
        '''
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  Integer
        @return: Number of mutated forms this primitive can take
        '''

        return len(self.fuzz_library) + len(self.this_library)

    def render(self):
        '''
        Render the primitive, encode the string according to the specified encoding.
        '''

        # try to encode the string properly and fall back to the default value on failure.
        try:
            self.rendered = str(self.value).encode(self.encoding)
        except:
            self.rendered = str(self.value).encode('latin-1')

        return self.rendered


########################################################################################################################
class bit_field(base_primitive):
    def __init__(self, value, width, max_num=None, endian="<", format="binary", signed=False, full_range=False, fuzzable=True, name=None):
        '''
        The bit field primitive represents a number of variable length and is used to define all other integer types.

        @type  value:      Integer
        @param value:      Default integer value
        @type  width:      Integer
        @param width:      Width of bit fields
        @type  endian:     Character
        @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  format:     String
        @param format:     (Optional, def=binary) Output format, "binary" or "ascii"
        @type  signed:     Boolean
        @param signed:     (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        @type  full_range: Boolean
        @param full_range: (Optional, def=False) If enabled the field mutates through *all* possible values.
        @type  fuzzable:   Boolean
        @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:       String
        @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
        '''

        super(bit_field, self).__init__()
        assert isinstance(width, int)

        if isinstance(value, (int, list, tuple)):
            self.value = self.original_value = value
        else:
            raise ValueError("The supplied value must be either an Int, Long, List or Tuple.")

        self.width = width
        self.max_num = max_num
        self.endian = endian
        self.format = format
        self.signed = signed
        self.full_range = full_range
        self.fuzzable = fuzzable
        self.name = name

        self.rendered = b""        # rendered value
        self.cyclic_index = 0         # when cycling through non-mutating values

        if self.max_num is None:
            self.max_num = self.to_decimal("1" + "0" * width)

        assert isinstance(self.max_num, int)

        # build the fuzz library.
        if self.full_range:
            # add all possible values.
            for i in range(0, self.max_num):
                self.fuzz_library.append(i)
        else:
            if isinstance(value, (list, tuple)):
                # Use the supplied values as the fuzz library.
                for val in value:
                    self.fuzz_library.append(val)
            else:
                # try only "smart" values.
                self.add_integer_boundaries(0)
                self.add_integer_boundaries(self.max_num // 2)
                self.add_integer_boundaries(self.max_num // 3)
                self.add_integer_boundaries(self.max_num // 4)
                self.add_integer_boundaries(self.max_num // 8)
                self.add_integer_boundaries(self.max_num // 16)
                self.add_integer_boundaries(self.max_num // 32)
                self.add_integer_boundaries(self.max_num)

        # if the optional file '.fuzz_ints' is found, parse each line as a new entry for the fuzz library.
        try:
            fh = open(".fuzz_ints", "r")

            for fuzz_int in fh.readlines():
                # convert the line into an integer, continue on failure.
                try:
                    fuzz_int = int(fuzz_int, 16)
                except:
                    continue

                if fuzz_int < self.max_num:
                    self.fuzz_library.append(fuzz_int)

            fh.close()
        except:
            pass

    def add_integer_boundaries(self, integer):
        '''
        Add the supplied integer and border cases to the integer fuzz heuristics library.

        @type  integer: Int
        @param integer: Integer to append to fuzz heuristics
        '''

        for i in range(-10, 10):
            case = integer + i

            # ensure the border case falls within the valid range for this field.
            if 0 <= case < self.max_num:
                if case not in self.fuzz_library:
                    self.fuzz_library.append(case)

    def render(self):
        '''
        Render the primitive.
        '''

        #
        # binary formatting.
        #

        if self.format == "binary":
            bit_stream = ""
            rendered = b""

            # pad the bit stream to the next byte boundary.
            if self.width % 8 == 0:
                bit_stream += self.to_binary()
            else:
                bit_stream = "0" * (8 - (self.width % 8))
                bit_stream += self.to_binary()

            # convert the bit stream from a string of bits into raw bytes.
            for i in range(len(bit_stream) // 8):
                chunk = bit_stream[8 * i:8 * i + 8]
                rendered += struct.pack("B", self.to_decimal(chunk))

            # if necessary, convert the endianess of the raw bytes.
            if self.endian == "<":
                rendered = rendered[::-1]

            self.rendered = rendered

        #
        # ascii formatting.
        #

        else:
            # if the sign flag is raised and we are dealing with a signed integer (first bit is 1).
            if self.signed and self.to_binary()[0] == "1":
                max_num = self.to_decimal("1" + "0" * (self.width - 1))

                # mask off the sign bit.
                val = self.value & self.to_decimal("1" * (self.width - 1))

                # account for the fact that the negative scale works backwards.
                val = max_num - val - 1

                # toss in the negative sign.
                self.rendered = "%d" % ~val

            # unsigned integer or positive signed integer.
            else:
                self.rendered = "%d" % self.value
        return self.rendered

    def to_binary(self, number=None, bit_count=None):
        '''
        Convert a number to a binary string.

        @type  number:    Integer
        @param number:    (Optional, def=self.value) Number to convert
        @type  bit_count: Integer
        @param bit_count: (Optional, def=self.width) Width of bit string

        @rtype:  String
        @return: Bit string
        '''
        if number is None:
            if isinstance(self.value, (list, tuple)):
                # We have been given a list to cycle through that is not being mutated...
                if self.cyclic_index == len(self.value):
                    # Reset the index.
                    self.cyclic_index = 0
                number = self.value[self.cyclic_index]
                self.cyclic_index += 1
            else:
                number = self.value

        if bit_count is None:
            bit_count = self.width

        return "".join(map(lambda x: str((number >> x) & 1), range(bit_count - 1, -1, -1)))

    def to_decimal(self, binary):
        '''
        Convert a binary string to a decimal number.

        @type  binary: String
        @param binary: Binary string

        @rtype:  Integer
        @return: Converted bit string
        '''

        return int(binary, 2)


########################################################################################################################
class byte (bit_field):
    def __init__(self, value, endian="<", format="binary", signed=False, full_range=False, fuzzable=True, name=None):
        self.s_type = "byte"
        if not isinstance(value, (int, list, tuple)):
            value = struct.unpack(endian + "B", value)[0]

        bit_field.__init__(self, value, 8, None, endian, format, signed, full_range, fuzzable, name)


########################################################################################################################
class word (bit_field):
    def __init__(self, value, endian="<", format="binary", signed=False, full_range=False, fuzzable=True, name=None):
        self.s_type = "word"
        if not isinstance(value, (int, list, tuple)):
            value = struct.unpack(endian + "H", value)[0]

        bit_field.__init__(self, value, 16, None, endian, format, signed, full_range, fuzzable, name)


########################################################################################################################
class dword (bit_field):
    def __init__(self, value, endian="<", format="binary", signed=False, full_range=False, fuzzable=True, name=None):
        self.s_type = "dword"
        if not isinstance(value, (int, list, tuple)):
            value = struct.unpack(endian + "L", value)[0]

        bit_field.__init__(self, value, 32, None, endian, format, signed, full_range, fuzzable, name)


########################################################################################################################
class qword (bit_field):
    def __init__(self, value, endian="<", format="binary", signed=False, full_range=False, fuzzable=True, name=None):
        self.s_type = "qword"
        if not isinstance(value, (int, list, tuple)):
            value = struct.unpack(endian + "Q", value)[0]

        bit_field.__init__(self, value, 64, None, endian, format, signed, full_range, fuzzable, name)
