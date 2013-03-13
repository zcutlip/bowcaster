import sys

BigEndian,LittleEndian=range(2)

class Logging:
    WARN=0
    INFO=1
    DEBUG=2
    prefixes=[]
    prefixes.append(" [!] ")
    prefixes.append(" [+] ")
    prefixes.append(" [@] ")
    
    def log_msg_start(self,msg,level=INFO):
        pref=Logging.prefixes[level]
        self.logfile.write(pref+msg)
        self.logfile.flush()

    def log_msg_end(self,msg):
        self.logfile.write("%s\n" % msg)
        self.logfile.flush()

    def log_msg(self,msg,level=INFO):
        msg="%s\n"%msg
        self.log_msg_start(msg,level)

    def LOG_INFO(self,msg):
        self.log_msg(msg,level=Logging.INFO)

    def LOG_WARN(self,msg):
        self.log_msg(msg,level=Logging.WARN)

    def LOG_DEBUG(self,msg):
        self.log_msg(msg,level=Logging.DEBUG)


    def __init__(self,logfile=None):
        self.logfile=sys.stdout
        if logfile:
            self.logfile=open(logfile,"a")

    def set_log_file(self,logfile):
        if not self.logfile == sys.stdout:
            self.logfile.close()
        self.logfile=open(logfile,"a")
    
    def set_log_stdout(self,logfile):
        if not self.logfile == sys.stdout:
            self.logfile.close()
            self.logfile=sys.stdout

