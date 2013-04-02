

import urllib
import urllib2

class HttpClient(object):
    def encode(self,data):
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
        
        
