#!/usr/bin/env python

"""
Example code to upload a firmware file to the Netgear R6200 firmware update form.
"""

import sys
import os
from bowcaster.common import Logging
from bowcaster.clients import HttpClient
from bowcaster.clients import HTTPError
from bowcaster.clients import MultipartForm

def send_fw(url,fw_file):
    
    logger=Logging(max_level=Logging.DEBUG)
    logger.LOG_INFO("Sending %s" % fw_file)
    logger.LOG_INFO("to %s" % url)

    fw_file_basename=os.path.basename(fw_file)
    
    logger.LOG_INFO("Creating headers.")
    headers={"Accept":
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    headers["Accept-Language"]="en-US,en;q=0.5"
    headers["Accept-Encoding"]="gzip, deflate"
    headers["Referer"]="http://192.168.127.141/UPG_upgrade.htm"

    #admin:password
    headers["Authorization"]="Basic YWRtaW46cGFzc3dvcmQ="
    headers["Connection"]="keep-alive"

    logger.LOG_INFO("Creating post data")
    
    mf=MultipartForm()
    mf.add_field("buttonHit","Upgrade")
    mf.add_field("buttonValue","Upload")
    mf.add_field("IS_check_upgrade","0")
    mf.add_field("ver_check_enable","1")
    mf.add_file("mtenFWUpload",fw_file)
    mf.add_field("upfile",fw_file_basename)
    mf.add_field("Upgrade","Upload")
    mf.add_field("progress","")
    post_data=str(mf)
    headers["Content-Length"]=("%s" % len(post_data))
    headers["Content-Type"]=mf.get_content_type()
    client=HttpClient()
    logger.LOG_INFO("Sending request.")
    resp=client.send(url,headers=headers,post_data=post_data,logger=logger)
    
    return resp
    
    
    
def main(fw_file,host=None):
    if not host:
        host="192.168.127.141"
    url="http://%s/upgrade_check.cgi" % host
    resp=send_fw(url,fw_file)
    print resp

if __name__ == "__main__":
    if(len(sys.argv) == 2):
        main(sys.argv[1])
    elif len(sys.argv) == 3:
        main(sys.argv[1],host=sys.argv[2])
    else:
        print("Specify at least firmware file.")
        sys.exit(1)

    