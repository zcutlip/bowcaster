#!/usr/bin/env python
import sys

from bowcaster.development.overflowconfig import OverflowConfigParser
from bowcaster.common.support import Logging

def main(configfile,outfile):
    logger=Logging()
    logger.LOG_DEBUG("Config file: %s" % configfile)
    buffer_overflow=OverflowConfigParser(configfile)
    open(outfile,"w").write(str(buffer_overflow.overflow_buf))

if __name__=="__main__":
    main(sys.argv[1],sys.argv[2])
