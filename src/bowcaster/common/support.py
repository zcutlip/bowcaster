# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 
import sys
import binascii

def pretty_string(string):
    p_string=""
    for byte in string:
        if ord(byte) >= 32 and ord(byte) <= 126:
            p_string+=byte
        else:
            p_string+="\\x"+binascii.hexlify(byte)
    return p_string

BigEndian,LittleEndian=range(2)
"""
Endianness constants to pass to constructors ofendianness-sensitive classes.
"""
def parse_badchars(badchars):
    badchar_list=[]
    for item in badchars:
        if type(item)==int:
            badchar_list.append(chr(item))
        else:
            if type(item) == str:
                parts=list(item)
                for part in parts:
                    badchar_list.append(part)
    return badchar_list

class Logging:
    """
    Basic logging class. Prints to stdout by default.

    Attributes
    ----------
    WARN, INFO, DEBUG: Constants for log levels.

    """
    WARN=0
    INFO=1
    DEBUG=2
    prefixes=[]
    prefixes.append(" [!] ")
    prefixes.append(" [+] ")
    prefixes.append(" [@] ")

    def __init__(self,logfile=None):
        self.logfile=sys.stdout
        if logfile:
            self.logfile=open(logfile,"a")

    def log_msg_start(self,msg,level=INFO):
        """
        Print the start of a log message with level decorator, but no newline.

        Parameters
        ----------
        msg: String to print
        level: one of the Logging class's level attributes
        """
        pref=Logging.prefixes[level]
        self.logfile.write(pref+msg)
        self.logfile.flush()

    def log_msg_end(self,msg):
        """
        Print the start of a log message with NO level decorator, but with a newline.
        """
        self.logfile.write("%s\n" % msg)
        self.logfile.flush()

    def log_msg(self,msg,level=INFO):
        """
        Print a log message prefixed with level decorator and terminated with a newline.
        """
        msg="%s\n"%msg
        self.log_msg_start(msg,level)

    def LOG_INFO(self,msg):
        """
        Convenience method for INFO log level.
        """
        self.log_msg(msg,level=Logging.INFO)

    def LOG_WARN(self,msg):
        """
        Covenience method for the WARN log level.
        """
        self.log_msg(msg,level=Logging.WARN)

    def LOG_DEBUG(self,msg):
        """
        Convenience method for the DEBUG log level.
        """
        self.log_msg(msg,level=Logging.DEBUG)

    def set_log_file(self,logfile):
        """
        Set the file to use for logging to <logfile>.

        <logfile> will be opened for appending and will become the destination
        for all future log output.
        """
        if not self.logfile == sys.stdout:
            self.logfile.close()
        self.logfile=open(logfile,"a")

    def set_log_stdout(self,logfile):
        """
        Set log output to stdout.
        """
        if not self.logfile == sys.stdout:
            self.logfile.close()
            self.logfile=sys.stdout

