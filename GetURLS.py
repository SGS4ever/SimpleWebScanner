import requests
import bs4
from bs4 import BeautifulSoup
import lxml
import re
import os

url_list = []
para_list = []

def GetAll(url, num = 30):
    k = url.split('/')
    url_path = k[0] + "//" + k[2]
    new = 0
#    print("requesting..." + url + '\n')
#    print("url_path..." + url_path + '\n')
    if len(url_list) >= 30 or len(url_list) >= num:
                    #print("To save your time... 30urls at most...")
                    return 0
#    if url.endswith("help/") or url.endswith("help"):
#        return 0
    s = requests.session()
    response = s.get(url) # 你需要的网址
    if not response:
        print("connect error")
        return 0
    soup = BeautifulSoup(response.text, 'lxml')
    for link in soup.find_all('a'):
        if link.get('href'):
           if link['href'].startswith("http") and link['href'] not in url_list:
               url_list.append(link['href'])
               new += 1
               if len(url_list) >= 30 or len(url_list) >= num:
                        #print("To save your time... 30urls at most...")
                        return 0
           elif link['href'].startswith(".."):
               url_new = url_path + link['href'][2:]
               if url_new not in url_list:
                   url_list.append(url_new)
                   new += 1
                   if len(url_list) >= 30 or len(url_list) >= num:
                        #print("To save your time... 30urls at most...")
                        return 0
           else:
               url_new = url_path + link['href']
               if url_new not in url_list:
                   url_list.append(url_new)
                   new += 1
                   if len(url_list) >= 30 or len(url_list) >= num:
                        #print("To save your time... 30urls at most...")
                        return 0
    #a标签中的链接添加完毕，以下添加onclick事件中的href
    node = str(soup.find_all(string = re.compile('href'))) #找到文本中含有 href 的元素
    href_list = re.findall(r'href\s\=\s"+[0-9a-zA-Z\/\?\=\_\&]*"+|href="+[0-9a-zA-Z\/\?\&\_\&]*"+', node)  #在元素中匹配 href="..." 或者 href = "..."的字符串
    for iter in href_list:
        match = re.search(r'"+[0-9a-zA-Z\/\?\=\_\&]*"+', iter)
        if not match.group(0) in para_list:
            para_list.append(match.group(0))   #将href中的地址写入para_list
#    print(para_list)
    
    #window.location.href 添加完毕，下面查找window.open
    node = str(soup.find_all(string = re.compile('window\.open')))
    open_list = re.findall(r'window.open\([0-9a-zA-Z\.\"\/\_\?\&\=]*\)', node)
    for iter in open_list:
        match = re.search(r'"+[0-9a-zA-Z\.\"\/\_\?\&\=]*"+', iter)
        if not match.group(0) in para_list:
            para_list.append(match.group(0))
    #地址添加完毕
    for i in range(len(para_list)):
        para = para_list[i]
        match = re.search(r'[0-9a-zA-Z\/\.\?\&\=\_\:]+', para)
        para_list[i] = match.group(0) if match else para_list[i]
        if para_list[i].startswith("http") and para_list[i] not in url_list and re.search(url_path, para_list[i]):
            url_list.append(para_list[i])
            new += 1
            if len(url_list) >= 30 or len(url_list) >= num:
                    #print("To save your time... 30urls at most...")
                    return 0
        elif para_list[i].startswith(".."):
               url_new = url_path + para_list[i][2:]
               if url_new not in url_list and re.search(url_path, url_new):
                   url_list.append(url_new)
                   new += 1
                   if len(url_list) >= 30 or len(url_list) >= num:
                        #print("To save your time... 30urls at most...")
                        return 0
        else:
            url_new = url_path + para_list[i]
            if url_new not in url_list and re.search(url_path, url_new):
                url_list.append(url_new)
                new += 1
                if len(url_list) >= 30 or len(url_list) >= num:
                    #print("To save your time... 30urls at most...")
                    return 0
        
#    print(open_list)
#    print(para_list)
#    for para in para_list:
#        if url.endswith('/') and para.startswith('/'):
#            url_new = url[0:len(url) - 1] + para
#            if url_new not in url_list:
#                url_list.append(url_new)
#                new += 1
#        elif not url.endswith('/') and not para.startswith('/'):
#            url_new = url + '/' + para
#            url_list.append(url_new)
#            new += 1
#        else:
#            url_new = url + para
#            url_list.append(url_new)
#            new += 1
#    r = len(url_list)
#    while(i < r):
#        url_item = url_list[i]
#        if not url_item.startswith("http"): #当前url不以 http开头，组合出http形式的url
#           if url_item.startswith('/') and url.endswith('/'):
#                url_new = url[0:len(url) - 1] + url_item
#                if url_new not in url_list:
#                    url_list[i] = url_new
#                    new += 1
#                else: #组合出新的url之后发现重复
#                    del url_list[i]
#            elif url_item.startswith("../") and url.endswith('/'):
#                url_new = url + url_item[3:]
#                if url_new not in url_list:
#                    url_list[i] = url_new
#                    new += 1
#                else: #组合出新的url之后发现重复
#                    del url_list[i]
#            else:
#                url_new = url + url_item
#                if url_new not in url_list:
#                    url_list[i] = url_new
#                    new += 1
#                else: #组合出新的url之后发现重复
#                    del url_list[i]
#        i += 1
#        r = len(url_list)
#   print(url_list)
    s.close()
    if new == 0:
        return 0
    else:
#        print("url list now:")
#        print(url_list)
        if len(url_list) >= 30 or len(url_list) >= num:
            return 0
        for url_item in url_list:
            GetAll(url_item)
            
def WRITE_SUB_URL(url, num):
    GetAll(url, num)
    with open("newfile.txt", 'a+') as suburls:
         for i in range(100):
            suburls.write("*")
         suburls.writelines("\nTo save your time, 30 urls at most.\n")
         for url in url_list:
             suburls.write(url + '\n')
         suburls.writelines("\n")
    if os.path.exists('sub_urls.txt'):
        os.remove("sub_urls.txt")
        os.rename("newfile.txt", 'sub_urls.txt')
    else:
        os.rename("newfile.txt", 'sub_urls.txt')
    return 1

if __name__ == '__main__':
#    url = input("URL:")
#    WRITE_SUB_URL(url, 30)