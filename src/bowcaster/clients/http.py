# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 

import urllib
import urllib2
import mimetools
import itertools
import os
from urllib2 import HTTPError
from ..common.support import Logging

class HttpClient(object):
    """
    A very basic HTTP client class whose primary purpose is sending a string
    to a server via POST or GET, and to abstract the details of 
    """
    def encode(self,data):
        """
        If you need to control what data is URL encoded, use this, otherwise set
        urlencode=True on send()
        """
        if type(data) == dict:
            data=urllib.urlencode(data)
        else:
            data=urllib.quote_plus(data)
        return data
        
    def send(self,url,headers=None,post_data=None,urlencode=False,get_resp=True,debug_req=False):
        """
        Send HTTP data.  If post data is provided, the request is sent as a POST,
        otherwise it is sent as a GET.
        
        Note: For POST requests, Content-Length header is not calculated. It
        be provided in the headers parameter.
        
        Parameters
        ----------
        url:        URL to send the GET or POST to.
        headers:    Optional. A dictionary of header key/value pairs describing
                    the HTTP headers to send. Ordering is not guaranteed.
        post_data:  Optional. Data to send in a POST request. Defaults to None.
        urlencode:  Optional. URL encode the POST data. Defaults to False.
        get_resp:   Optional. A response is expected, and will be read() and
                    returned.  Defaults to true.
        debug_req:  Optional. Set debug level on the URL opener so that the
                    request is printed to the console.
        """
        
        if post_data and urlencode:
            post_data=self.encode(post_data)
            
        if post_data and headers:
            req = urllib2.Request(url,post_data,headers)
        elif post_data:
            req = urllib2.Request(url,post_data)
        elif headers:
            req = urllib2.Request(url,None,headers)
        else:
            req = urllib2.Request(url)
        
         
        #Instead of using urlib2.urlopen(),
        #Create a HTTPHandler object and optionally set its debug level to 1
        httpHandler = urllib2.HTTPHandler()
        if print_req:
            httpHandler.set_http_debuglevel(1)
        
        #Instead of using urllib2.urlopen, create an opener,
        #and pass the HTTPHandler and any other handlers... to it.
        opener = urllib2.build_opener(httpHandler)

        #Use your opener to open the Request.
        response = opener.open(req)               
        #response = urllib2.urlopen(req)
        
        resp_data=None
        if get_resp:
            resp_data = response.read()
        return resp_data

class MultipartForm(object):
    """

    A class to generate a multipart/form-data body for use with a POST request.
    Generate the multipart form string then send as a POST with the HttpClient
    class.
    
    Shamelessly ripped off from: http://pymotw.com/2/urllib2/
    """
    def __init__(self):
        self.form_fields=[]
        self.files=[]
        self.boundary=mimetools.choose_boundary()
    
    def get_content_type(self):
        """
        Return the content-type, including multipart boundary, for this object.
        """
        return "multipart/form-data; boundary=%s" % self.boundary
        
    def add_field(self,name,value):
        """
        Add a simple form field to the form data.
        
        Parameters
        ----------
        name:   Name of the field to add.
        value:  Value of the field to add.
        """
        self.form_fields.append((name,value))
    
    
    def add_file(self,fieldname,filename,filename_override=None,mimetype=None):
        """
        Add a file to be uploaded.
        
        Parameters
        ----------
        fieldname:  Textual field name for the form being submitted.
        filename:   Path and name of file on disk to open, read, and include in
                    the form data.
        filename_override:  Optional. Override the filename with this string.
                            Otherwise the basename of the filename parameter
                            will be used in the form data.
        mimetype:   Mimetype to specify for the attached file. If none, defaults
                    to: 'application/octet-stream'
        """
        body=open(filename,"rb").read()
        file_basename=""
        if filename_override != None:
            file_basename=filename_override
        else:
            file_basename=os.path.basename(filename)
        
        if mimetype == None:
            mimetype='application/octet-stream'
        
        self.files.append((fieldname,file_basename,mimetype,body))
    
    def __str__(self):
        """
        Get a string representation of the form data suitable for use as
        post_data parameter to HttpClient.send()
        """
        parts=[]
        part_boundary = "--" + self.boundary
        parts.extend(
            [ part_boundary,
              'Content-Disposition: form-data; name="%s"' % name,
               '',
               value,
            ]
            for name,value in self.form_fields
        )
        
        parts.extend(
            [ part_boundary,
                'Content-Disposition: file; name="%s"; filename="%s"' % \
                 (field_name,filename),
                 'Content-Type: %s' % content_type,
                 '',
                 body,
              ]
              for field_name,filename,content_type,body in self.files
        )
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')
        return '\r\n'.join(flattened)