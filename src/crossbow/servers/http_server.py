#!/usr/bin/env python
# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 

import os

import urlparse
from BaseHTTPServer import HTTPServer,BaseHTTPRequestHandler

class LimitedHTTPServer(HTTPServer):
    def __init__(self,server_address,handler_class,docroot=None,files_to_serve=[]):
        self.docroot=docroot
        if not docroot:
            self.docroot=os.getcwd()
        self.files_to_serve=[]
        for filename in files_to_serve:
            if not filename.startswith("/"):
                filename="/"+filename
            self.files_to_serve.append(filename)

        HTTPServer.__init__(self,server_address,handler_class)
    def has_file(self,filename):
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

class LimitedHTTPRequestHandler(BaseHTTPRequestHandler):
    def __sanitize_path__(self):
        while '/../' in self.path:
            self.path=self.path.replace("/../","/")

    def do_GET(self):
        print self.server.docroot
        self.__sanitize_path__()
        print self.path
        print urlparse.urlparse(self.path)
        file_exists=True
        if self.server.has_file(self.path):
            try:
                f=open(self.server.docroot+self.path)
                self.send_response(200)
                self.send_header('Content-type','application/octet-stream')
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
                self.server.remove_file(self.path)
            except Exception as e:
                print e
                file_exists=False
        else:
            print "Server doesn't have file: %s" % self.path
            file_exists=False

        if not file_exists:
            self.send_error(404,'File Not found: %s' % self.path)



if __name__ == "__main__":
    server_address=('',8080)
    httpd=LimitedHTTPServer(server_address,LimitedHTTPRequestHandler,files_to_serve=["file1","file2"])
    #httpd=LimitedHTTPServer(server_address,LimitedHTTPRequestHandler,files_to_serve=[])
    keep_going=True
    try:
        while keep_going:
            if httpd.more_files():
                print "Handling request"
                httpd.handle_request()
            else:
                print "No more files."
                keep_going=False
    except KeyboardInterrupt:
        print "Interrupted."
        keep_going=False


    print "Shutting down"
    httpd.socket.close()

