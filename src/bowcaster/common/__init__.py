# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 

from support import *
from hackers.hackers import *

__all__ = ["BigEndian","LittleEndian","Logging"]

hackers_quotes=None
try:
    hacker_quotes_enabled=getattr(sys.modules['__main__'],'HACKERS_QUOTES_ENABLED')
except:
    hacker_quotes_enabled=False
if True == hacker_quotes_enabled:
    hackers_quotes=Hackers()
    hackers_quotes.banner()
