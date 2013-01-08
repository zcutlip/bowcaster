#!/usr/bin/env python
#
#Copyright (C) 2013  Zachary Cutlip [uid000_at_gmail_dot_com]
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


import struct
import binascii

class OverflowBuffer:
    """A buffer overflow builder that generates a pattern of a desired length and replaces
    parts of that pattern with replacement objects such as ROP addresses and a payload string.

    Arguments:
    length -- Length of overflow buffer to build.
    overflow_sections -- List of OverflowSection and RopGadget objects to substitute
        into the base overflow string.
    """
    #TODO: Means of specifying a list of bad chars to avoid and to check for.
    
    @classmethod        
    def pattern_create(cls,requested_length):

        #TODO: This this generic and more elegant. Maybe with recursion.
        #TODO: Filter out bad chars
        upper_alpha=list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        lower_alpha=list("abcdefghijklmnopqrstuvwxyz")
        numerals=list("0123456789")

        maxlen=len(upper_alpha)*len(lower_alpha)*len(numerals)
        buildlen=maxlen if requested_length > maxlen else requested_length
        pattern=""
        try:
            for upperchar in upper_alpha:
                for lowerchar in lower_alpha:
                    for numberchar in numerals:
                        subpattern="%c%c%c"%(upperchar,lowerchar,numberchar)
                        remaining = buildlen-len(pattern)
                        if remaining <= 0:
                            raise Exception
                        elif remaining <= 3:
                            pattern+=subpattern[0:remaining]
                        else:
                            pattern+=subpattern
        except:
            if maxlen < requested_length:
                pattern+=pattern[0:(requested_length-maxlen)]


        return pattern
                            


    def __init__(self,length,overflow_sections):
        self.overflow_sections=overflow_sections
        ostr=self.__class__.pattern_create(length)
        if len(ostr) < length:
            raise Exception("Maximum overflow length is only %d. Can't build string %d long.\n" %(len(ostr),length))
        for osect in overflow_sections:
            if (osect.offset + len(osect.value)) > len(ostr):
                raise Exception("Overflow replacement section not within bounds of overflow string\n"+\
                    "Name: %s\nOffset: %d\nLength: %d\noverflow string needs to be %d long to fit" % (osect.name_string,osect.offset,len(osect.value),osect.offset+len(osect.value)))
            ostr=ostr[:osect.offset]+\
                osect.value+\
                ostr[osect.offset+len(osect.value):]

        self.overflow_string=ostr
    
    def find_offset(self,string):
       return self.overflow_string.find(string)

    def __str__(self):
        string=""
        for byte in self.overflow_string:
            if ord(byte) >= 32 and ord(byte) <= 126:
                string+=byte
            else:
                string+="\\x"+binascii.hexlify(byte)

        return self.overflow_string



class OverflowSection(object):
    """A an object used to replace some subset of the 
    base overflow string with a given string at a given offset. For example,
    Replace a section of the base overflow string with your payload.
    An exception will be raised if the section is too long to replace at the given offset.
    
    Arguments:
    offset -- Offset at which to replace the base overflow string.
    value -- String with which to replace part of the base overflow string.
    name_string -- A descriptive name for this replacement section.
    """

    def __init__(self,offset,value,name_string):
        self.offset=offset
        self.value=value
        self.name_string=name_string

    def __str__(self):
        return self.name_string

class RopGadget(OverflowSection):
    """An object that can replace a 4-byte subset of the
    base overflow string with a given address at a given offset.
    
    NOTE: This is only compatible with 32-bit addresses.

    Arguments:
    endianness -- BigEndian or LittleEndian, the endianess the value should be converted to.
    offset -- The offset into the base overflow string .
    rop_address -- Memory address to replace the base overflow string at the given offset. e.g.,
        the address of the desired ROP gadget.
    name_string -- A descriptive name for this object.
    base_address -- an optional base address to add to your memory address. Useful when target
            libraries get loaded at varying addresses such as in live vs. emulated environments.
    """
    BigEndian,LittleEndian=range(2)

    def __init__(self,endian,offset,rop_address,name_string,base_address=0):
        format_str=""
        if endian==self.__class__.BigEndian:
            format_str=">L"
        else:
            format_str="<L"
            
        rop_bytes=struct.pack(format_str,rop_address+base_address)
        super(self.__class__,self).__init__(offset,rop_bytes,name_string)

if __name__=="__main__":
    overflow_sections=[]
    # overflow_sections.append(OverflowSection(396,"AAAAAAAA","my string of As"))
    qemu_libc_base=0x40942000
    rop_g=RopGadget(RopGadget.BigEndian,0,0x1eb10,"one two three four rop gadget",qemu_libc_base)
    
    overflow_sections.append(rop_g)
   
    try:
        ofb=OverflowBuffer(48,overflow_sections)
    except Exception,e:
        print e
        exit(1)
    print str(ofb)
    
