import struct
import string
from ...common.support import BigEndian,LittleEndian


class Trampoline(object):
    MaxBackJump=-0x20000
    MaxFwdJump=0x1fffc
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
        if (offset < self.__class__.MaxBackJump or 
                offset > 0x1fffc):
            raise Exception("Offst %d is outside of %d backwards or %d forwards." % 
                    (offset,self.__class__.MaxBackJump,self.__class__.MaxFwdJump))
        self.endianness=endianness       
        self.shellcode=self.__class__.shellcodes[endianness]

        packedbytes=struct.pack(">h",(offset>>2))
        
        low_byte=packedbytes[1]
        high_byte=packedbytes[0]
        
        self.shellcode=self.shellcode.replace("HIHI",high_byte)
        self.shellcode=self.shellcode.replace("LOLO",low_byte)
        


