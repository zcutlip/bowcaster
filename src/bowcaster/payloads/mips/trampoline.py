# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 
import struct
import string
from collections import OrderedDict
from ...common.support import BigEndian,LittleEndian
from ...common.support import pretty_string
from ...common import hackers_quotes

class Trampoline(object):
    """
    A small (8 byte) trampoline payload.

    Attributes
    ----------
    MAX_BACK_JUMP: The maximum negative offset that can be encoded into the branch.
    MAX_FWD_JUMP: The maximum positive offset that can be encoded into the branch.

    """
    MAX_BACK_JUMP=-0x20000
    MAX_FWD_JUMP=0x1fffc
    shellcodes={}
    shellcodes[BigEndian] = string.join([
        "\x11\xefHIHILOLO",    # beq	t7,t7,0xffff0010
        "\x01\xe0\x78\x26"    # xor	t7,t7,zero
	],'')
    shellcodes[LittleEndian] = string.join([
        "LOLOHIHI\xef\x11",    # beq    t7,t7,0x20000
        "\x26\x78\xe0\x01"    # xor t7,t7,zero
    ],'')

    def __init__(self,endianness,offset):
        """
        Class constructor.

        Parameters
        ----------
        endianness: Endianness of the target system. (See the support.BigEndian
            and support.LittleEndian)
        offset: Positive or negative offset to jump.

        Raises EncoderException if the offset is outside of the MAX_BACK_JUMP -
            MAX_FWD_JUMP range.
            
        Note: 1028, or 0x0404, is the smallest amount you can trampoline forward
             without a NULL byte in the encoded beq instruction.
        Note: Remember, the program counter has already advanced +4 from whatever
              the location is of this payload object. So your jump offset will be
              relative to this object's offset+4.
        """
        if (offset < self.__class__.MAX_BACK_JUMP or
                offset > self.__class__.MAX_FWD_JUMP):
            raise EncoderException("Offset %d is outside of %d backwards or %d forwards." %
                    (offset,self.__class__.MAX_BACK_JUMP,self.__class__.MAX_BACK_JUMP))
        self.endianness=endianness
        self.shellcode=self.__class__.shellcodes[endianness]

        #TODO: is this endianness-safe?
        packedbytes=struct.pack(">h",(offset>>2))

        low_byte=packedbytes[1]
        high_byte=packedbytes[0]

        self.shellcode=self.shellcode.replace("HIHI",high_byte)
        self.shellcode=self.shellcode.replace("LOLO",low_byte)
        
        if hackers_quotes:
            hackers_quotes.log_random_quote()

        self.details=details=OrderedDict()
        details["jump_offset"]=offset

    def pretty_string(self):
        return pretty_string(self.shellcode)
        
    @classmethod
    def reconstitute(cls,details):
        offset=int(details["jump_offset"],0)
        endianness=details["endianness"]
        
        return cls(endianness,offset)

