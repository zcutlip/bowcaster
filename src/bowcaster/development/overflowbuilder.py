# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 
import struct

from ..common.support import Logging
from ..common.support import BigEndian,LittleEndian
from ..common.support import pretty_string
from ..common.support import parse_badchars

class OverflowBuilderException(Exception):
    pass

class OverflowBuffer(object):
    """
    Primary overflow builder class.

    Generates a buffer of a desired length filled with a generated pattern.
    Replaces parts of that pattern with replacement objects such as ROP
    addresses and a payload string.
    """

    def __init__(self,endianness,length,overflow_sections=None,logger=None):
        """
        Class constructor.

        Parameters
        ----------
        length: Length of overflow buffer to build.
        overflow_sections: List of OverflowSection objects to substitute
            into the base overflow string.
        logger: Optional logger object. If none is provided, a logger will be
            instantiated with output to stdout.

        Attributes
        ----------


        Raises OverflowBuilderException
        """

        self.overflow_string=None
        self.endianness=endianness
        self.logger=logger
        if not self.logger:
            self.logger=Logging()
        if None == overflow_sections:
            overflow_sections = []

        self.overflow_sections=overflow_sections
        ostr=PatternSection.pattern_create(length)
        if len(ostr) < length:
            raise OverflowBuilderException("Maximum overflow length is only %d. Can't build string %d long.\n" %(len(ostr),length))
        for osect in overflow_sections:
            if (osect.offset + len(osect.section_string)) > len(ostr):
                err="Overflow replacement section not within bounds of overflow string\n"+\
                    "Name: %s\nOffset: %d\nLength: %d\noverflow string needs to be %d long to fit" \
                    % (osect.description,osect.offset,len(osect.section_string),osect.offset+len(osect.section_string))
                raise OverflowBuilderException(err)

            ostr=ostr[:osect.offset]+\
                osect.section_string+\
                ostr[osect.offset+len(osect.section_string):]
        problems=self.scan_for_overlaps(overflow_sections)
        if(len(problems) > 0):
            for k,v in problems.items():
                print str(k)
                print k.offset
                print len(k.section_string)
                message="Section \"%s\",\n\toffset: %d\n\tlength: %d\n\toverlaps with the following sections:" % (str(k),k.offset,len(k.section_string))
                self.logger.LOG_WARN(message)
                for section in v:
                    self.logger.LOG_WARN("\"%s\"\n\toffset: %d\n\tlength: %d" %
                        (str(section),section.offset,len(section.section_string)))

            raise OverflowBuilderException("Overlapping overflow sections.")

        self.overflow_string=ostr
    def len(self):
        """
        Returns length of the overflow buffer.
        """
        return len(self.overflow_string)

    def scan_for_overlaps(self,section_list):
        """
        Scan all overflow sections for overlaps with each other.

        Iterates over every section in the provided list checking for overlaps.
        The first section is checked against the remaining sections, then
        removed from the list.  Then the next section is checked against all
        remaining ones, and so forth until no unscanned sections removed.

        Parameters
        ----------
        section_list: List of sections to to check for overlaps.


        Note
        ----
        Returns a dictionary of problem sections, each one with a list of
        overlapping sections:
        {
         section_1:list_of_s1_overlapping_sections[...],
         section_2:list_of_s2_overlapping_sections[...]
        }
        An empty dictionary means there were no problems.
        """
        not_scanned=[]
        problems={}

        for sect in section_list:
            not_scanned.append(sect)

        while len(not_scanned) > 0:
            overlapping=[]
            sect=not_scanned.pop(0)
            for unscanned in not_scanned:
                if sect.overlaps_with(unscanned):
                    overlapping.append(unscanned)
                if len(overlapping) > 0:
                    problems[sect]=overlapping
        return problems


    def scan_for_nulls(self):
        """
        Scan the overflow string for NULL bytes.

        Returns a list of offsets in the overflow string where NULL bytes are
        located. An empty list means no NULL bytes were found.
        """
        offsets=[]
        current_offset=0

        for char in self.overflow_string:
            current_offset+=1
            if char == '\x00':
                offsets.append(current_offset)

        return offsets


    def find_offset(self,value):
        """Find a string in the overflow string.
        Returns offset where the string is found, or -1 if not found.
        See Python string.find() for semantic info.
        """
        string=value
        if isinstance(value,int):
            if self.endianness==BigEndian:
                format_str=">L"
            elif self.endianness == LittleEndian:
                format_str="<L"
            string=struct.pack(format_str,value)

        return self.overflow_string.find(string)

    def print_section_descriptions(self):
        self.logger.LOG_INFO("************************************")
        self.logger.LOG_INFO("Section Descriptions:")
        self.logger.LOG_INFO("")
        for section in self.overflow_sections:
            self.logger.LOG_INFO(section.description)
        self.logger.LOG_INFO("")
        self.logger.LOG_INFO("************************************")
    
    def __len__(self):
        return self.len()

    def __str__(self):
        return self.overflow_string

    def __repr__(self):
        return str(self)

    def pretty_string(self):
        return pretty_string(self.overflow_string)

class EmptyOverflowBuffer(OverflowBuffer):
    """
    Class for creating a zero-length overflow buffer object that can be extended
    by appending various overflow sections, such as ROP gadgets or strings.
    """
    def __init__(self,endianness,default_base=0,badchars=[],maxlength=0,logger=None):
        """
        Class constructor.

        Parameters
        ----------
        endianness: Endianness of the target system. (See the support.BigEndian
            and support.LittleEndian)
        default_base: Optional. The default base address to be used when
            computing ROP addresses.
        badchars: Optional. List of restricted bytes that must be avoided.
        maxlength: Optional. Maximum length of this buffer overflow.
            The objects add_* methods will enforce this length, if set.
        logger: Optional logger object. If none is provided, a logger will be
            instantiated with output to stdout.
        """

        self.default_base=default_base
        self.endianness=endianness
        self.badchars=parse_badchars(badchars)
        no_sections=[]
        no_length=0
        self.maxlength=maxlength
        self.sections=no_sections

        if not logger:
            logger=Logging()
        self.section_creator=SectionCreator(endianness,base_address=default_base,badchars=badchars,logger=logger)
        super(self.__class__,self).__init__(endianness,no_length,no_sections,logger=logger)

    def __add_section(self,section):
        newlength=self.len() + len(section.section_string)
        if self.maxlength and (newlength > self.maxlength ):
            overage=newlength-self.maxlength
            err=("Section \"%s\" exceeds maximum length of %d by %d bytes." %
                (section.description,self.maxlength,overage))
            raise OverflowBuilderException(err)
        self.overflow_sections.append(section)
        self.overflow_string=self.overflow_string+section.section_string

    def add_string(self,string,description=None):
        """
        Append a string seciton to the overflow buffer.

        Parameters
        ----------
        string: The string to append to the overflow buffer.
        description: Optional. A string describing this overflow section. If one
            is not provided, a generic one will be generated.  Useful for
            more readable logs and Exception messages.

        Raises OverflowBuilerException if this string would cause the overflow
            buffer to excited the specified maximum length
        """
        if not description:
            description=("String. Offset: %d, length: %d" % (self.len(),len(string)))
        section=self.section_creator.string_section(self.len(),string,description)
        self.__add_section(section)

    def add_pattern(self,length,description=None):
        """
        Generate and append a pattern.


        Generates a pattern based on the current offset in the buffer.  This
        ensures the location of substrings in this pattern will always be
        constant relative to the beginning of the buffer, even if this section
        is later moved forward or backwards or shortened or lengthened.

        Parameters
        ----------
        length: Length of the pattern to be generated.
        description: Optional. A string describing this overflow section. If one
            is not provided, a generic one will be generated.  Useful for
            more readable logs and Exception messages.

        Raises OverflowBuilerException if this string would cause the overflow
            buffer to excited the specified maximum length
        """
        pattern_section=self.section_creator.pattern_section(self.len(),length,description)
        self.__add_section(pattern_section)

    def add_rop_gadget(self,address,base_address=None,description=None):
        """
        Append a ROP gadget section to the overflow buffer.

        Parameters
        ----------
        address: The address in the library or executable the ROP gadget is
            found.
        base_address: Optional. The base address to be added to address
            to compute the ROP gadget's actual address in memory.  If not
            specified, then the default_base, if any, provided to the
            constructor is used instead.
        description: Optional. A string describing this overflow section. If one
            is not provided, a generic one will be generated.  Useful for
            more readable logs and Exception messages.

        Raises OverflowBuilerException if this string would cause the overflow
            buffer to excited the specified maximum length.
        """
        if None==base_address:
            base_address=self.default_base
        gadget=self.section_creator.gadget_section(self.len(),address,
                        base_address=base_address,description=description)
        self.__add_section(gadget)

class OverflowSection(object):
    """A class to represent a section of the overflow buffer.
    Replace some subset of the base overflow string with a given string at a
    given offset. For example, replace a section of the base overflow string
    with your payload, or with a strings of 'D's. An exception will be raised
    if the section is too long to replace at the given offset.
    """

    def __init__(self,offset,section_string,description=None,badchars=[],logger=None):
        """
        Class constructor.

        Parameters
        ----------
        offset: Offset in the buffer where this section should be located.
        section_string: The string that is appended to or inserted into the
            overflow buffer.
        description: Optional. A string describing this overflow section. If one
            is not provided, a generic one will be generated.  Useful for
            more readable logs and Exception messages.

        badchars: Optional. List of restricted bytes that must be avoided.
        logger: Optional logger object. If none is provided, a logger will be
            instantiated with output to stdout.
        """
        if not logger:
            logger=Logging()
        self.offset=offset
        self.section_string=section_string
        if not description:
            description = ("Generic overflow section. Offset %d, length %d" %
                 (offset,len(section_string)))

        self.description=description

        for char in badchars:
            if char in section_string:
                err=("Found bad byte %#04x\n\tin section: %s\n\tsection offset: %d"
                        % (ord(char),description,offset))
                raise(OverflowBuilderException(err))


    def __str__(self):
        """Returns string representation of this object."""
        return self.description

    def overlaps_with(self,osection):
        """
        Boolean test for whether another OverflowSection overlaps with this one.

        Parameters
        ----------
        osection: OverflowSection object to test for overlapping

        Returns True or False indicating whether this section overlaps with the
        provided one.
        """
        my_start=self.offset
        my_end=self.offset + len(self.section_string) - 1

        their_start=osection.offset
        their_end=osection.offset+len(osection.section_string) - 1

        if my_start >= their_start and my_start <= their_end:
            return True

        if their_start >= my_start and their_start <= my_end:
            return True

        return False

class PatternSection(OverflowSection):
    #TODO Create patterns that are free of specified bad characters
    #rather than raise exception.
    @classmethod
    def __prune_bad_chars(cls,chars,badchars):
        pruned=""
        for char in chars:
            if not char in badchars:
                pruned=pruned+char
        return list(pruned)

    @classmethod
    def pattern_create(cls,requested_length,badchars=[],logger=None):

        #TODO: Make this generic and more elegant. Maybe with recursion.

        upper_alpha=cls.__prune_bad_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ",badchars)
        lower_alpha=cls.__prune_bad_chars("abcdefghijklmnopqrstuvwxyz",badchars)
        numerals=cls.__prune_bad_chars("0123456789",badchars)

        if logger:
            logger.LOG_DEBUG("uppers: %s" % str(upper_alpha))
            logger.LOG_DEBUG("lowers: %s" % str(lower_alpha))
            logger.LOG_DEBUG("numerals: %s" % str(numerals))

        maxlen=len(upper_alpha)*len(lower_alpha)*len(numerals)
        buildlen=maxlen if requested_length > maxlen else requested_length
        pattern=""
        try:
            for upperchar in upper_alpha:
                for lowerchar in lower_alpha:
                    for numberchar in numerals:
                        subpattern="%c%c%c"%(upperchar,lowerchar,numberchar)
                        remaining = buildlen-len(pattern)
                        if remaining <= 0:
                            raise Exception
                        elif remaining <= 3:
                            pattern+=subpattern[0:remaining]
                        else:
                            pattern+=subpattern
        except:
            if maxlen < requested_length:
                pattern+=pattern[0:(requested_length-maxlen)]

        return pattern

    def __init__(self,offset,length,description=None,badchars=[],logger=None):
        """
        Class constructor.

        Parameters
        ----------
        offset: Offset in the buffer where this section should be located.
        length: Length of the pattern to be generated.
        description: Optional. A string describing this overflow section. If one
            is not provided, a generic one will be generated.  Useful for
            more readable logs and Exception messages.
        badchars: Optional. List of restricted bytes that must be avoided.
        logger: Optional logger object. If none is provided, a logger will be
            instantiated with output to stdout.

        """

        overall_length=offset+length
        pattern=self.__class__.pattern_create(overall_length,badchars=badchars,logger=logger)
        pattern=pattern[offset:offset+length]
        if not description:
            description=("Pattern at offset %d, length %d" % (offset,length))
        super(self.__class__,self).__init__(offset,pattern,description,badchars)


class RopGadget(OverflowSection):
    """
    A class to encode an integer into a four-byte section of the overflow buffer.

    The provided numerical value is packed into a four-byte string using the
    endianness.


    Note
    ----
    This is only compatible with 32-bit addresses.
    """

    def __init__(self,endian,offset,rop_address,description=None,base_address=0,badchars=[],logger=None):
        """Class constructor.

        Parameters
        ----------
        endianness: Endianness of the target system. (See the support.BigEndian
            and support.LittleEndian)
        offset: The offset into the base overflow string.
        rop_address: Memory address (or other 32-bit integral value) add or
            insert into the overflow buffer.
        description: Optional. A string describing this overflow section. If one
            is not provided, a generic one will be generated.  Useful for
            more readable logs and Exception messages.
        base_address: Optional. The base address to be added to address
            to compute the ROP gadget's actual address in memory.  If not
            specified, then the default_base, if any, provided to the
            constructor is used instead.
        badchars: Optional. List of restricted bytes that must be avoided.
        logger: Optional logger object. If none is provided, a logger will be
            instantiated with output to stdout.
        """

        format_str=""
        if endian==BigEndian:
            format_str=">L"
        elif endian == LittleEndian:
            format_str="<L"
        else:
            raise OverflowBuilderException("Unknown endianness specified in RopGadget")

        if not description:
            description = ("ROP gadget: offset %d, address %#010x" % (offset,rop_address+base_address))
        rop_bytes=struct.pack(format_str,rop_address+base_address)

        super(self.__class__,self).__init__(offset,rop_bytes,description=description,badchars=badchars)

class SectionCreator(object):
    """
    A factory for overflow section objects.

    Useful for hiding details of overflow section object creation such that
    parameters that are the same each time may be specified only once--during
    instantiation of the factory, rather than during each section's
    instantiation.
    """
    def __init__(self,endianness,base_address=0,badchars=[],logger=None):
        """
        Parameters
        ----------
        endianness: Endianness of the target system. (See the support.BigEndian
            and support.LittleEndian)
        base_address: Optional. The base address to be added to address
            to compute the ROP gadget's actual address in memory.  If not
            specified, then the default_base, if any, provided to the
            constructor is used instead.
        badchars: Optional. List of restricted bytes that must be avoided.
        logger: Optional logger object. If none is provided, a logger will be
            instantiated with output to stdout.
        """
        self.__section_list=[]
        self.endianness=endianness
        self.badchars=parse_badchars(badchars)
        self.base_address=base_address
        if not logger:
            logger=Logging()
        self.logger=logger
    
    def section_list():
        def fget(self):
            return self.__section_list
        return locals()
    
    section_list=property(**section_list())
    
    def string_section(self,offset,section_string,description=None):
        """
        Create a string section from the provided string
        """
        section=OverflowSection(offset,section_string,description,self.badchars)
        self.section_list.append(section)
        return section

    def pattern_section(self,offset,length,description=None):
        """
        Create a pattern section from the provided length and offset.
        """
        section=PatternSection(offset,length,description=description,badchars=self.badchars)
        self.section_list.append(section)
        return section

    def gadget_section(self,offset,rop_address,description=None,base_address=None):
        """
        Create a ROP gadget.

        Parameters
        ----------
        offset: The offset into the base overflow string.
        rop_address: Memory address (or other 32-bit integral value) add or
            insert into the overflow buffer.
        description: Optional. A string describing this overflow section. If one
            is not provided, a generic one will be generated.  Useful for
            more readable logs and Exception messages.
        base_address: Optional. The base address to be added to address
            to compute the ROP gadget's actual address in memory.  If not
            specified, then the default_base, if any, provided to the
            constructor is used instead.
        """
        if None==base_address:
            base_address=self.base_address
        section=RopGadget(self.endianness,offset,rop_address,
                        description=description,
                        base_address=base_address,
                        badchars=self.badchars,
                        logger=self.logger)
        
        self.section_list.append(section)
        return section
        
if __name__=="__main__":
    overflow_sections=[]
    # overflow_sections.append(OverflowSection(396,"AAAAAAAA","my string of As"))
    qemu_libc_base=0x40942000
    rop_g=RopGadget(BigEndian,0,0x1eb10,"one two three four rop gadget",qemu_libc_base)

    overflow_sections.append(rop_g)

    try:
        ofb=OverflowBuffer(48,overflow_sections)
    except Exception,e:
        print e
        exit(1)
    print str(ofb)

