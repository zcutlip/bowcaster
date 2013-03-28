# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 
import sys
import os
sys.path.insert(0,os.path.abspath('..'))

from crossbow.overflow_development.overflowbuilder import EmptyOverflowBuffer
from crossbow.common.support import BigEndian
from crossbow.common.support import Logging

logger=Logging()
logger.LOG_INFO("Creating empty overflow buffer")

buf=EmptyOverflowBuffer(BigEndian,badchars=['A','B','6'])
buf.add_pattern(1024)

logger.LOG_INFO("Length of empty overflow buffer: %d" % buf.len())

buf.print_section_descriptions()
print buf.pretty_string()

logger.LOG_INFO("Offet of \"u3Au4\": %d" % buf.find_offset("u3Au4"))




logger.LOG_INFO("Creating second emtpy overflow buffer")

buf2=EmptyOverflowBuffer(BigEndian,badchars=['A','B','6'])
try:
    buf2.add_pattern(128)
except Exception as e:
    logger.LOG_WARN("Failed to add section.")
    logger.LOG_WARN(str(e))

try:
    buf2.add_string('A'*128)
except Exception as e:
    logger.LOG_WARN("Failed to add section.")
    logger.LOG_WARN(str(e))

try:
    buf2.add_rop_gadget(0x4dc46fa0)
except Exception as e:
    logger.LOG_WARN("Failed to add section.")
    logger.LOG_WARN(str(e))

try:
    buf2.add_pattern(1024-buf2.len())
except Exception as e:
    logger.LOG_WARN("Failed to add section.")
    logger.LOG_WARN(str(e))


logger.LOG_INFO("Length of second empty overflow buffer: %d" % buf2.len())

buf2.print_section_descriptions()
print buf2.pretty_string()

logger.LOG_INFO("Offset of \"u3Au4\": %d" % buf2.find_offset("u3Au4"))
logger.LOG_INFO("Offset of \"M\\xc4o\\xa0\": %d" % buf2.find_offset("M\xc4o\xa0"))
logger.LOG_INFO("Offset of 0x4dc46fa0: %d" % buf2.find_offset(0x4dc46fa0))
