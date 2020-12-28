import time, requests, os, sys, re
import random, urllib
import datetime,itertools
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from bs4 import BeautifulSoup as BS
import json
from string import whitespace
import difflib, http.client, itertools, optparse, random, re, urllib, urllib.parse, urllib.request  # Python 3 required
import SQLScan
import WebCrack
import XSSModul
import GetURLS
import fileupload

log_file = 'web_crack_log.txt'
oklog_file = 'web_crack_ok.txt'

exp_user_dic = ["admin' or 'a'='a", "'or'='or'", "admin' or '1'='1' or 1=1", "')or('a'='a", "'or 1=1--"]
exp_pass_dic = exp_user_dic
NAME, VERSION, AUTHOR, LICENSE = "Damn Small SQLi Scanner (DSSS) < 100 LoC (Lines of Code)", "0.3a", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

PREFIXES, SUFFIXES = (" ", ") ", "' ", "') "), ("", "-- -", "#", "%%16")            # prefix/suffix values used for building testing blind payloads
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')                                        # characters used for SQL tampering/poisoning of parameter values
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")                                     # boolean tests used for building testing blind payloads
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                             # optional HTTP header names
GET, POST = "GET", "POST"                                                           # enumerator-like values used for marking current phase
TEXT, HTTPCODE, TITLE, HTML = range(4)                                             # enumerator-like values used for marking content type
FUZZY_THRESHOLD = 0.95                                                              # ratio value in range (0,1) used for distinguishing True from False responses
TIMEOUT = 30                                                                        # connection timeout in seconds
RANDINT = random.randint(1, 255)                                                    # random integer value used across all tests
BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)" # regular expression used for recognition of generic firewall blocking messages

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
output_report_frame = '''
   <!DOCTYPE html>\n<head>\n<meat charset='utf-8' />\n<title>ScanReport</title>\n<link rel="stylesheet" href="https://cdn.staticfile.org/twitter-bootstrap/3.3.7/css/bootstrap.min.css">\n
   <script src="https://cdn.staticfile.org/jquery/2.1.1/jquery.min.js"></script>\n<script src="https://cdn.staticfile.org/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>\n
   <style>body{font-family: "Italic";font-size: 20px;background-image: url(report.jpg);background-size: cover;}\n
   h1{font-family:"Times New Roman";font-size: 50px; text-align: center; text-shadow: 2px 2px gray}\n
   table {margin-top: 3%; font-size: 30px;color: black;font-weight: bolder;}
   </style>
   </head>\n<body>\n<div class="container-fluid">\n<div class="row">\n<div class="col-md-12">\n
   <h1>GL_SCAN_REPORT</h1>\n</div>\n</div>
   <div class="row">\n<div class="col-md-12">\n
'''
output_report_table = '''
   <h4>Target:TARGET_URL</h4>\n
   <table class="table table-hover">\n<tr>\n<td class="col-md-2">CHECK_TYPE</td>\n<td class="col-md-2">RESULT</td>\n
   <td class="col-md-8">INFO</td>\n</tr>
'''
output_report_WEB = '''
   \n<tr>\n<td>Weak_Password</td>\n<td>WEB_FLAG</td>\n<td class="col-md-8">U_NAME  PW</td>\n</tr>
'''

output_report_SQL = '''
   \n<tr>\n<td>SQL</td>\n<td>SQL_FLAG</td>\n<td class="col-md-8">SQL_PAYLOAD</td>\n</tr>
'''

output_report_XSS = '''
   \n<tr>\n<td>XSS</td>\n<td>XSS_FLAG</td>\n<td class="col-md-8">XSS_PAYLOAD</td>\n</tr>
'''

output_report_FILE = '''
   \n<tr>\n<td>File</td>\n<td>FILE_FLAG</td><td class="col-md-8">FILE_PAYLOAD</td>\n</tr>
'''
output_report_frame2 = '''
    \n</table>\n</div>\n</div>\n</div>\n</body>\n</html>
'''

if __name__ == '__main__':
    print("*****************************************")
    print("*                                       *")
    print("* Based On DSSS & WebCracker & BruteXSS *")
    print("*  Developed by XunruiGuo & LuzheLian   *")
    print("*                                       *")
    print("*****************************************")
    print("File or URL:\n")
    while (1):
        print("[+] Choose [Q]uit or [S]tart: [+]:")
        o = input()
        if (o == 'Q'):
            print("QUITED\n")
            break
        if (o != 'S'):
            print("[-] Illegal input! [-]")
            continue
        print("[+] URL or URL_FILE to scan [+]:")
        url_file_name = input()
        url1 = url2 = url3 = url4 = url_file_name
        try:
            if url_file_name.startswith("http"):      
                print("WebCracking...")
                WEB_FLAG, U_NAME, PW = WebCrack.web_crack_task(url = url1)   #直接把输入作为目标URL
                print("Scanning SQL Injection...")
                print("It may cost a long time to scan SQL Injection...")
                SQL_FLAG, SQL_PAYLOAD = SQLScan.sql_scan(url = url2)
                print("Scanning XSS...")
                print("It may cost a long time to scan XSS...")
                XSS_FLAG, XSS_PAYLOAD = XSSModul.XSSScan(url = url3)
                print("Scanning FlieUpload...")
                FILE_FLAG, FILE_PAYLOAD = fileupload.FileScan(url = url4)
                print("\nScanning the web...")
                GetURLS.WRITE_SUB_URL(url4, 30)
                print("30paths of the web has been wrote to sub_urls.txt.")
                print("If you can't find the file, there may be some error")

                output_report_frame3 = output_report_frame
                output_report_table2 = output_report_table
                output_report_WEB2 = output_report_WEB
                output_report_SQL2 = output_report_SQL
                output_report_XSS2 = output_report_XSS
                output_report_FILE2 = output_report_FILE
                output_report_frame4 = output_report_frame2
                with open('ScanReport_tmp.html', 'a+') as res:
                    res.write(output_report_frame)
                    output_report_table = re.sub(r'TARGET_URL', url_file_name, output_report_table);
                    res.write(output_report_table)
                    if WEB_FLAG == 1:
                        output_report_WEB = re.sub(r'WEB_FLAG', 'SUCCESS', output_report_WEB)
                        output_report_WEB = re.sub(r'U_NAME', U_NAME, output_report_WEB)
                        output_report_WEB = re.sub(r'PW', PW, output_report_WEB)
                    elif WEB_FLAG == -1 or WEB_FLAG == -3:
                        output_report_WEB = re.sub(r'WEB_FLAG', 'FAIL', output_report_WEB)
                        output_report_WEB = re.sub(r'U_NAME', 'Nothing founded.', output_report_WEB)
                        output_report_WEB = re.sub(r'PW', PW, output_report_WEB)
                    elif WEB_FLAG == -2:
                        output_report_WEB = re.sub(r'WEB_FLAG', 'ERROR', output_report_WEB)
                        output_report_WEB = re.sub(r'U_NAME', 'Connect error or anything else.', output_report_WEB)
                        output_report_WEB = re.sub(r'PW', PW, output_report_WEB)
                    elif WEB_FLAG == -3:
                        output_report_WEB = re.sub(r'WEB_FLAG', 'FAIL', output_report_WEB)
                        output_report_WEB = re.sub(r'U_NAME', 'No forms in the page.', output_report_WEB)
                        output_report_WEB = re.sub(r'PW', PW, output_report_WEB)
                    res.write(output_report_WEB)

                    if SQL_FLAG == 1:
                        output_report_SQL = re.sub(r'SQL_FLAG', 'ERROR_BASED_INJECTION', output_report_SQL)
                    elif SQL_FLAG == 2:
                        output_report_SQL = re.sub(r'SQL_FLAG', 'BOOL_BASED_INJECTION', output_report_SQL)
                    else:
                        output_report_SQL = re.sub(r'SQL_FLAG', 'FAIL', output_report_SQL)
                    if SQL_PAYLOAD != '': 
                        output_report_SQL = re.sub(r'SQL_PAYLOAD', SQL_PAYLOAD, output_report_SQL)
                    else:
                        output_report_SQL = re.sub(r'SQL_PAYLOAD', 'May be not nulnerable', output_report_SQL)
                    res.write(output_report_SQL)

                    if XSS_FLAG == 1:
                        output_report_XSS = re.sub(r'XSS_FLAG', 'REFLECTIVE_XSS', output_report_XSS)
                    elif XSS_FLAG == 2:
                        output_report_XSS = re.sub(r'XSS_FLAG', 'STORABLE_XSS', output_report_XSS)
                    else:
                        output_report_XSS = re.sub(r'XSS_FLAG', 'FAIL', output_report_XSS)
                    XSS_PAYLOAD = XSS_PAYLOAD.replace('<', '&lt;');
                    XSS_PAYLOAD = XSS_PAYLOAD.replace('>', '&gt;');
                    XSS_PAYLOAD = XSS_PAYLOAD.replace('/', '&#47;');
                    XSS_PAYLOAD = XSS_PAYLOAD.replace('\\', '&#92;');
                    if XSS_PAYLOAD != '':
                        output_report_XSS = re.sub(r'XSS_PAYLOAD', XSS_PAYLOAD, output_report_XSS)
                    else:
                        output_report_XSS = re.sub(r'XSS_PAYLOAD', 'May be not vulnerable', output_report_XSS)
                    res.write(output_report_XSS)

                    if FILE_FLAG == 1:
                         output_report_FILE = re.sub(r'FILE_FLAG', 'vulnerable', output_report_FILE)
                    else:
                         output_report_FILE = re.sub(r'FILE_FLAG', 'not found', output_report_FILE)
                    output_report_FILE = re.sub(r'FILE_PAYLOAD', FILE_PAYLOAD, output_report_FILE)
                    res.write(output_report_FILE)
                    res.write(output_report_frame2)

                if os.path.exists("ScanReport.html"):
                    os.remove("ScanReport.html")
                    os.rename("ScanReport_tmp.html", 'ScanReport.html')
                else:
                    os.rename("ScanReport_tmp.html", 'ScanReport.html')
                print("A SCAN_RESULT REPORT HAS BEEN PRODUCED! IN THE CURRENT PATH TO VIEW IT.\n")

                output_report_frame = output_report_frame3
                output_report_table = output_report_table2
                output_report_WEB = output_report_WEB2
                output_report_SQL = output_report_SQL2
                output_report_XSS = output_report_XSS2
                output_report_FILE = output_report_FILE2
                output_report_frame2 = output_report_frame4
            else:
                print("[-] Illegal URL [-]\n[!] Using URL such as 'http://test.com' [!]\n")
        except Exception as e:
            start = datetime.datetime.now()
            with open('web_crack_error.txt', 'a+') as error_log:
                error_log.write(str(start) + str(e) + '\n')
            print(start, e)