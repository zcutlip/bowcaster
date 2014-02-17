import random
import os
from ...common.support import Logging

class Hackers():
    HACKERS_FILE="hackers.txt"
    STARS="*************************"
    
    def __get_this_path(self):
        thisfile=__file__
        if os.path.islink(thisfile):
            thisfile=os.path.realpath(thisfile)

        thispath=os.path.dirname(os.path.abspath(thisfile))
        return thispath
    
    def __init__(self,logger=None):
        cls=self.__class__
        thispath=self.__get_this_path()
        if not logger:
            logger=Logging(max_level=Logging.DEBUG)
        self.logger=logger
        self.hackers_quotes=[]
        
        hackers_file="%s/%s" % (thispath,cls.HACKERS_FILE)
        
        for line in open(hackers_file,"rb").readlines():
            self.hackers_quotes.append(line.rstrip())
    def banner(self):
        self.logger.LOG_INFO("Hackers quotes enabled.")
        
    def random_quote(self):
        random.seed()
        rand=random.randint(1,len(self.hackers_quotes))-1
        return self.hackers_quotes[rand]
        
        
    def log_random_quote(self,logger=None):
        if not logger:
            logger=self.logger
            
        quote=self.random_quote()
        logger.LOG_DEBUG("%s" % self.__class__.STARS)
        logger.LOG_DEBUG("Hackers random movie quote:")
        logger.LOG_DEBUG("%s" % quote)
        logger.LOG_DEBUG("%s" % self.__class__.STARS)
        
