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
        If you need to URL encode data on your own, use this,
        otherwise set urlencode=True on send()
        """
        if type(data) == dict:
            data=urllib.urlencode(data)
        else:
            data=urllib.quote_plus(data)
        return data
        
    def send(self,url,headers=None,post_data=None,urlencode=False,get_resp=True):
        if post_data and urlencode:
            post_data=self.encode(post_data)
            
        if post_data and headers:
            req = urllib2.Request(url,post_data,headers)
        elif post_data:
            req = urllib2.Request(url,post_data)
        elif headers:
            req = urllib2.Request(url,headers)
        else:
            req = urllib2.Request(url)
        
        response = urllib2.urlopen(req)
        
        if get_resp:
            resp_data = response.read()
        return resp_data
        
        
