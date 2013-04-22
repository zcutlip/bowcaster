# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 

import urllib
import urllib2

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
        
    def send(self,url,headers=None,post_data=None,urlencode=False,get_resp=True):
		"""
		Send HTTP data.  If post data is provided, the request is sent as a POST,
		otherwise it is sent as a GET.
		
        Parameters
        ----------
		url:		URL to send the GET or POST to.
		headers: 	Optional. A dictionary of header key/value pairs describing
					the HTTP headers to send. Ordering is not guaranteed.
		post_data:	Optional. Data to send in a POST request. Defaults to None.
		urlencode:	Optional. URL encode the POST data. Defaults to False.
		get_resp:	Optional. A response is expected, and will be read() and
					returned.  Defaults to true.
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
        
        response = urllib2.urlopen(req)
        
        if get_resp:
            resp_data = response.read()
        return resp_data