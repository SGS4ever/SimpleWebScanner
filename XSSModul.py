import requests
import bs4
from bs4 import BeautifulSoup
import lxml
import re
import random
import itertools
import GetURLS


requests.packages.urllib3.disable_warnings()

BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)"
key_str = r"R0xfVEVTVElORw==SEFWRVlPVVhTUw=="
def get_form(url):
    url1 = url.strip()
    header = random_headers()
    res = requests.get(url1, timeout=10, verify=False, headers=header)
    res.encoding = res.apparent_encoding
    html = res.text
    all_soup = BeautifulSoup(html, "lxml")
    for forms in all_soup.find_all('form'):
        captchas = ['验证码', '验 证 码','点击更换', '点击刷新','看不清','认证码','安全问题']
        for captcha in captchas:
             if captcha in forms:
                 print("[-]" + captcha + " in page: " + url + '\n')
                 return '',''
    #总而言之，有验证码就结束爆破
    try:
        title = all_soup.title.text
    except:
        title = ''
    result = re.findall(".*<form (.*)</form>.*", html, re.S)
    #得到form标签往下所有的内容
    #如 <form id="...">
    #就从id=开始
    form_data = ''
    form_content = ''
    if result:
        form_data = '<form ' + result[0] + ' </form>' #整个表单部分的代码

        form_soup = BeautifulSoup(form_data, "lxml")

        form_content = form_soup.form #表单去除了标签

#        print(type(form_data), type(form_soup), type(form_content))
    return form_content, title

def random_headers():#生成随机headers
    user_agent = ['Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
                  'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60',
                  'Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
                  'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5']
    UA = random.choice(user_agent)
    a = str(random.randint(1, 255))
    b = str(random.randint(1, 255))
    c = str(random.randint(1, 255))
    random_XFF = '127.' + a + '.' + b + '.' + c
    random_CI = '127.' + c + '.' + a + '.' + b
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UA,
        'X-Forwarded-For': random_XFF,
        'Client-IP':random_CI,
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        "Referer": "http://www.baidu.com/",
        'Content-Type': 'application/x-www-form-urlencoded'}
    return headers

def wordlistimport(file,lst):       #此处有缩进
	try:
		with open(file,'r') as f: #Importing Payloads from specified wordlist.
			print("[+] Loading Payloads from specified wordlist...")
			for line in f:
				final = str(line.replace("\n",""))
				lst.append(final)
	except IOError:
		print("[!] Wordlist not found!")

def XSSScan(url):
    REFLACTED_XSS = 1
    STOREABLE_XSS = 2
    flag = 0
    payload = ''
    value = []
    payload_list = []
    url_try_list = []
    form_para_list = []
    form_value = []
    i = 0
    method = "both"

    for i in range(len(url)):
        if url[i] == '?':
            break
    #print(i)
    if i != len(url) - 1:
        url_path = url[0:i]
        para_list = re.findall(r'\?[0-9a-zA-Z\_]*\=[0-9a-zA-Z\_]*|\&[0-9a-zA-Z\_]*\=[0-9a-zA-Z\_\#]*', url)
#    print(para_list)
        for i in range(len(para_list)):
            para = para_list[i]
            value.append(para.split('=')[1])
            para = para.split('=')[0][1:]
            para_list[i] = para
    else:
        url_path = url
        para_list = []
    content, title = get_form(url)  #通过表单得知消息发送的信息
    if content != '':
        if re.findall(r'method=".*"|method = ".*"', str(content)):
            method = re.findall(r'method=".*"|method = ".*"', str(content))[0]
            method = re.findall(r'get|post', method)[0]
            method = method.lower()
        if re.findall(r'action=".*"|action = ".*"', str(content)):
            action = re.findall(r'action=".*"|action = ".*"', str(content))[0]
            action = re.findall(r'".*"', action)[0]
            action = re.findall(r'[0-9a-zA-Z\_\/]*', action)[0]
        for x in content.find_all('input'):
            if x.has_attr('name') and not x['name'] in form_para_list:
                form_para_list.append(x['name'])    #用于发送post请求
                para_list.append(x['name'])
                if x.has_attr('value'):
                    form_value.append(x['value'])
                    value.append(x['value'])
                else:
                    form_value.append('')
                    value.append('')
        for x in content.find_all('select'):
            if x.has_attr('name'):
                if not x['name'] in form_para_list:
                    form_para_list.append(x['name'])
                    para_list.append(x['name'])
                    if x.has_attr('value'):
                        form_value.append(x['value'])
                        value.append(x['value'])
                    else:
                        form_value.append('')
                        value.append('')

    wordlistimport("wordlist.txt", payload_list)  # 导入payload

    s = requests.session()      #开始请求
    res_ori = s.get(url)
    soup_ori = BeautifulSoup(res_ori.text, 'lxml')
    if re.search(BLOCKED_IP_REGEX, str(soup_ori.find_all('html'))):
        print('request BLOCKED')
        payload = "request BLOCKED"
        return flag, payload

    if method == 'get' or method == 'both':
        for j in range(len(payload_list)):
            for i in range(len(para_list)):
                for k in range(len(para_list)):
                    if k == 0 and k == i:
                        url_try = url_path + '?' + para_list[k] + '=' + payload_list[j]
                    elif k == 0 and k != i:
                        url_try = url_path + '?' + para_list[k] + '=' + value[k]
                    elif k != 0 and k == i:
                        url_try = url_try + '&' + para_list[k] + '=' + payload_list[j]
                    else: #k != 0 and k != 0
                        url_try = url_try + '&' + para_list[k] + '=' + value[k]
                    url_try_list.append(url_try)
    #    print(url_try_list

        for i in range(len(url_try_list)):
    #        print("TRYING..." + url_try_list[i])
            res_try = s.get(url_try_list[i])
            soup_try = BeautifulSoup(res_try.text, 'lxml')
            #print(soup_try)
            if re.search(key_str, soup_try.get_text()):
                flag = REFLACTED_XSS
                payload = url_try_list[i]
                return flag, payload              #get方法结束

    if method == 'post' or method == 'both':
        data = {}
        GetURLS.WRITE_SUB_URL(url, 5)
        for i in range(len(payload_list)):
            for k in range(len(form_para_list)):
                for j in range(len(form_para_list)):
                    if k == j:
                        data[form_para_list[j]] = form_value[j] + payload_list[i]
                    else:
                        data[form_para_list[j]] = form_value[j]
                print("POSTING..." + str(data))
                res_try = s.post(url, data)     #发送数据
                soup_try = BeautifulSoup(res_try.text, 'lxml')
    #            print(res_try.text)
                if re.search(key_str, str(soup_try.find_all('html'))):    #如果返回的界面中就有key_str，仍是反射型
                    flag = REFLACTED_XSS
                    payload = "method:POST| data=" + str(data)
                    return flag, payload
                res_again = s.get(url)    #再次请求
                soup_again = BeautifulSoup(res_again.text, 'lxml')
                if re.search(key_str, str(soup_again.find_all('html'))):
                    flag = STOREABLE_XSS                              #再次请求得到key_str，是存储型
                    payload = "method:POST| data=" + str(data)
                    return flag, payload
                with open('sub_urls.txt', 'r') as suburl:    #打开其他链接
                    for line in suburl:
                        if not line.startswith("http"):
                            continue
                        res_again = s.get(line)
                        soup_again = BeautifulSoup(res_again.text, 'lxml')
                        if re.search(key_str, str(soup_again.find_all('html'))):
                            flag = STOREABLE_XSS
                            payload = "method:POST| data=" + str(data)
                            return flag, payload
    return flag, payload


if __name__ == '__main__':
    url = input("URL:")
    print(XSSScan(url))
    